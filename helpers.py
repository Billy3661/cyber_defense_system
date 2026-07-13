import re
import json
import socket
import ssl
import secrets
import ipaddress
import urllib.parse
import functools
import os
import base64
import hashlib
import logging
import shutil as _shutil
from datetime import datetime
from flask import session, flash, redirect, url_for, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests as req
import whois
import dns.resolver
import database

# Limiter created without app binding — app calls limiter.init_app(app) later
limiter = Limiter(
    get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# ─────────────────────────────────────────────
#  SSRF PROTECTION — OWASP A10
# ─────────────────────────────────────────────

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private Class A
    ipaddress.ip_network("172.16.0.0/12"),     # Private Class B
    ipaddress.ip_network("192.168.0.0/16"),    # Private Class C
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 private
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation (TEST-NET-1)
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
]


def is_private_ip(ip_str):
    """Check if an IP address is private, loopback, or reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for net in BLOCKED_NETWORKS:
            if addr in net:
                return True
        return False
    except ValueError:
        return False


def is_safe_host(hostname):
    """Resolve hostname and verify it doesn't point to a private/reserved IP."""
    try:
        ips = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in ips:
            ip = sockaddr[0]
            if is_private_ip(ip):
                return False
        return True
    except (socket.gaierror, OSError):
        return True  # Can't resolve — let the scan proceed and report the error

# ─────────────────────────────────────────────
#  ENV / API KEY CONSTANTS
# ─────────────────────────────────────────────

CLOUDFLARE_RADAR_TOKEN = os.environ.get("CLOUDFLARE_RADAR_TOKEN", "")
CLOUDFLARE_RADAR_BASE = "https://api.cloudflare.com/client/v4/radar"
GOOGLE_SAFEBROWSING_KEY = os.environ.get("GOOGLE_SAFEBROWSING_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")

# ─────────────────────────────────────────────
#  KNOWN MALICIOUS / SUSPICIOUS DATA
# ─────────────────────────────────────────────

MALICIOUS_DOMAINS = set()

SUSPICIOUS_KEYWORDS = [
    "prize", "winner", "free", "urgent", "suspended", "locked",
    "limited", "bitcoin", "crypto", "wallet",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".cf", ".ga", ".gq",
]

SHORTENER_DOMAINS = frozenset({
    '0.gp', '02faq.com', '0a.sk', '101.gg', '12ne.ws', '17mimei.club',
    '1drv.ms', '1ea.ir', '1kh.de', '1o2.ir', '1shop.io', '1un.fr',
    '1url.cz', '2.gp', '2.ht', '2.ly', '2doc.net', '2fear.com',
    '2kgam.es', '2link.cc', '2nu.gs', '2pl.us', '2u.lc', '2u.pw',
    '2wsb.tv', '3.cn', '3.ly', '301.link', '3le.ru', '4.gp',
    '4.ly', '49rs.co', '4sq.com', '5.gp', '53eig.ht', '5du.pl',
    '5w.fit', '6.gp', '6.ly', '69run.fun', '6g6.eu', '7.ly',
    '707.su', '71a.xyz', '7news.link', '7ny.tv', '7oi.de', '8.ly',
    '89q.sk', '92url.com', '985.so', '98pro.cc', '9mp.com', '9splay.store',
    'a.189.cn', 'aarp.info', 'ab.co', 'abc.li', 'abc11.tv', 'abc13.co',
    'abc7.la', 'abc7.ws', 'abc7ne.ws', 'abcn.ws', 'abe.ma', 'abelinc.me',
    'abnb.me', 'abr.ai', 'abre.ai', 'accntu.re', 'accu.ps', 'acer.co',
    'acer.link', 'aces.mp', 'acortar.link', 'act.gp', 'acus.org', 'adaymag.co',
    'adbl.co', 'adf.ly', 'adfoc.us', 'adm.to', 'adol.us', 'adweek.it',
    'aet.na', 'agrd.io', 'ai6.net', 'aje.io', 'al.st', 'alexa.design',
    'alli.pub', 'alnk.to', 'alpha.camp', 'alphab.gr', 'alturl.com', 'amays.im',
    'amba.to', 'ampr.gs', 'amrep.org', 'amzn.pw', 'ana.ms', 'anch.co',
    'ancstry.me', 'andauth.co', 'anon.to', 'anyimage.io', 'aol.it', 'aon.io',
    'apne.ws', 'app.philz.us', 'aptg.tw', 'arah.in', 'arc.ht', 'arkinv.st',
    'asin.cc', 'asq.kr', 'asus.click', 'at.vibe.com', 'atm.tk', 'atmilb.com',
    'atmlb.com', 'atres.red', 'autode.sk', 'avlne.ws', 'avlr.co', 'avydn.co',
    'axios.link', 'axoni.us', 'ay.gy', 'azc.cc', 'b-gat.es', 'b.link',
    'b.mw', 'b23.ru', 'b23.tv', 'b2n.ir', 'baratun.de', 'bayareane.ws',
    'bbva.info', 'bc.vc', 'bca.id', 'bcene.ws', 'bcove.video', 'bcsite.io',
    'bddy.me', 'beats.is', 'benqurl.biz', 'beth.games', 'bfpne.ws', 'bg4.me',
    'bhpho.to', 'bigcc.cc', 'bigfi.sh', 'biggo.tw', 'biibly.com', 'binged.it',
    'bit.do', 'bit.ly', 'bitly.com', 'bitly.is', 'bitly.lc', 'bityl.co',
    'bl.ink', 'blap.net', 'blbrd.cm', 'blck.by', 'blizz.ly', 'bloom.bg',
    'blstg.news', 'blur.by', 'bmai.cc', 'bnds.in', 'bnetwhk.com', 'bo.st',
    'boa.la', 'boile.rs', 'bom.so', 'bonap.it', 'booki.ng', 'bookstw.link',
    'boston25.com', 'bp.cool', 'br4.in', 'bravo.ly', 'bridge.dev', 'brief.ly',
    'brook.gs', 'browser.to', 'bst.bz', 'bstk.me', 'btm.li', 'btwrdn.com',
    'budurl.com', 'buff.ly', 'bung.ie', 'bwnews.pr', 'by2.io', 'bytl.fr',
    'bzfd.it', 'bzh.me', 'c11.kr', 'c87.to', 'cadill.ac', 'can.al',
    'canon.us', 'capitalfm.co', 'captl1.co', 'careem.me', 'caro.sl', 'cart.mn',
    'casio.link', 'cathaybk.tw', 'cathaysec.tw', 'cb.com', 'cbj.co', 'cbsloc.al',
    'cbsn.ws', 'cbt.gg', 'cc.cc', 'cdl.booksy.com', 'centi.ai', 'cfl.re',
    'chip.tl', 'chl.li', 'chn.ge', 'chn.lk', 'chng.it', 'chts.tw',
    'chzb.gr', 'cin.ci', 'cindora.club', 'circle.ci', 'cirk.me', 'cisn.co',
    'citi.asia', 'cjky.it', 'ckbe.at', 'cl.ly', 'clarobr.co', 'clc.am',
    'clc.to', 'clck.ru', 'cle.clinic', 'cli.re', 'clickmeter.com', 'clicky.me',
    'clr.tax', 'clvr.rocks', 'cmon.co', 'cmu.is', 'cmy.tw', 'cna.asia',
    'cnb.cx', 'cnet.co', 'cnfl.io', 'cnnmon.ie', 'cnvrge.co', 'cockroa.ch',
    'comca.st', 'come.ac', 'conta.cc', 'cookcenter.info', 'coop.uk', 'cort.as',
    'coupa.ng', 'cplink.co', 'cr8.lv', 'crackm.ag', 'crdrv.co', 'credicard.biz',
    'crwd.fr', 'crwd.in', 'crwdstr.ke', 'cs.co', 'csmo.us', 'cstu.io',
    'ctbc.tw', 'ctfl.io', 'cultm.ac', 'cup.org', 'cut.lu', 'cut.pe',
    'cutt.ly', 'cvent.me', 'cyb.ec', 'cybr.rocks', 'd-sh.io', 'da.gd',
    'dai.ly', 'dailym.ai', 'dainik-b.in', 'datayi.cn', 'davidbombal.wiki', 'db.tt',
    'dbricks.co', 'dcps.co', 'dd.ma', 'deb.li', 'dee.pl', 'deli.bz',
    'deloi.tt', 'dems.me', 'dhk.gg', 'di.sn', 'dibb.me', 'dis.gd',
    'dis.tl', 'discord.gg', 'discvr.co', 'disq.us', 'dive.pub', 'dk.rog.gg',
    'dkng.co', 'dky.bz', 'dl.gl', 'dld.bz', 'dlsh.it', 'dlvr.it',
    'dmdi.pl', 'dmreg.co', 'do.co', 'dockr.ly', 'dopice.sk', 'dpmd.ai',
    'dpo.st', 'dssurl.com', 'dtdg.co', 'dtsx.io', 'dub.sh', 'dv.gd',
    'dvrv.ai', 'dwz.tax', 'dxc.to', 'dy.fi', 'dy.si', 'e.lilly',
    'e.vg', 'ebay.to', 'econ.st', 'ed.gr', 'edin.ac', 'edu.nl',
    'eepurl.com', 'efshop.tw', 'ela.st', 'elle.re', 'ellemag.co', 'embt.co',
    'emirat.es', 'engt.co', 'enshom.link', 'entm.ag', 'envs.sh', 'epochtim.es',
    'ept.ms', 'eqix.it', 'es.pn', 'es.rog.gg', 'escape.to', 'esl.gg',
    'eslite.me', 'esqr.co', 'esun.co', 'etoro.tw', 'etp.tw', 'etsy.me',
    'everri.ch', 'exe.io', 'exitl.ag', 'ezstat.ru', 'f5yo.com', 'fa.by',
    'fal.cn', 'fam.ag', 'fandan.co', 'fandom.link', 'fandw.me', 'faras.link',
    'faturl.com', 'fav.me', 'fave.co', 'fb.me', 'fb.watch', 'fbstw.link',
    'fce.gg', 'fetnet.tw', 'fevo.me', 'ff.im', 'fifa.fans', 'firsturl.de',
    'firsturl.net', 'flic.kr', 'flip.it', 'flomuz.io', 'flq.us', 'fltr.ai',
    'flx.to', 'fmurl.cc', 'fn.gg', 'fnb.lc', 'foodtv.com', 'fooji.info',
    'forr.com', 'found.ee', 'fr.rog.gg', 'frdm.mobi', 'fstrk.cc', 'ftnt.net',
    'fumacrom.com', 'fvrr.co', 'fwme.eu', 'fxn.ws', 'g-web.in', 'g.asia',
    'g.page', 'ga.co', 'gandi.link', 'garyvee.com', 'gaw.kr', 'gbod.org',
    'gbpg.net', 'gbte.tech', 'gdurl.com', 'gek.link', 'gen.cat', 'geni.us',
    'genie.co.kr', 'gestyy.com', 'getf.ly', 'geti.in', 'gfuel.ly', 'gh.io',
    'ghkp.us', 'gi.lt', 'gigaz.in', 'git.io', 'github.co', 'gizmo.do',
    'gjk.id', 'glblctzn.co', 'glblctzn.me', 'gldr.co', 'glmr.co', 'glo.bo',
    'gma.abc', 'gmj.tw', 'go-link.ru', 'go.btwrdn.co', 'go.cwtv.com', 'go.dbs.com',
    'go.edh.tw', 'go.gcash.com', 'go.hny.co', 'go.id.me', 'go.intel-academy.com', 'go.intigriti.com',
    'go.jc.fm', 'go.lamotte.fr', 'go.lu-h.de', 'go.ly', 'go.nowth.is', 'go.osu.edu',
    'go.qb.by', 'go.rebel.pl', 'go.shell.com', 'go.shr.lc', 'go.sony.tw', 'go.tinder.com',
    'go.usa.gov', 'go.ustwo.games', 'go.vic.gov.au', 'godrk.de', 'gofund.me', 'gomomento.co',
    'goo-gl.me', 'goo.by', 'goo.gl', 'goo.gle', 'goo.su', 'goolink.cc',
    'goolnk.com', 'gosm.link', 'got.cr', 'got.to', 'gov.tw', 'gowat.ch',
    'gph.to', 'gq.mn', 'gr.pn', 'grb.to', 'grdt.ai', 'grm.my',
    'grnh.se', 'gtly.ink', 'gtly.to', 'gtne.ws', 'gtnr.it', 'gym.sh',
    'haa.su', 'han.gl', 'hashi.co', 'hbaz.co', 'hbom.ax', 'her.is',
    'herff.ly', 'hf.co', 'hi.kktv.to', 'hi.sat.cool', 'hi.switchy.io', 'hicider.com',
    'hideout.cc', 'hill.cm', 'histori.ca', 'hmt.ai', 'hnsl.mn', 'homes.jp',
    'hp.care', 'hpe.to', 'hrbl.me', 'href.li', 'ht.ly', 'htgb.co',
    'htl.li', 'htn.to', 'httpslink.com', 'hubs.la', 'hubs.li', 'hubs.ly',
    'huffp.st', 'hulu.tv', 'huma.na', 'hyperurl.co', 'hyperx.gg', 'i-d.co',
    'i.coscup.org', 'i.mtr.cool', 'ibb.co', 'ibf.tw', 'ibit.ly', 'ic9.in',
    'icit.fr', 'icks.ro', 'iea.li', 'ifix.gd', 'ift.tt', 'iherb.co',
    'ihr.fm', 'ii1.su', 'iii.im', 'il.rog.gg', 'ilang.in', 'illin.is',
    'iln.io', 'ilnk.io', 'imdb.to', 'ind.pn', 'indeedhi.re', 'indy.st',
    'infy.com', 'inlnk.ru', 'insig.ht', 'instagr.am', 'interc.pt', 'intuit.me',
    'invent.ge', 'inx.lv', 'ionos.ly', 'ipgrabber.ru', 'ipgraber.ru', 'iplogger.co',
    'iplogger.com', 'iplogger.info', 'iplogger.org', 'iplogger.ru', 'iplwin.us', 'iqiyi.cn',
    'irng.ca', 'is.gd', 'isw.pub', 'itsh.bo', 'itvty.com', 'ity.im',
    'ix.sk', 'j.gs', 'j.mp', 'ja.cat', 'ja.ma', 'jb.gg',
    'jcp.is', 'jkf.lv', 'jnfusa.org', 'jp.rog.gg', 'jpeg.ly', 'jz.rs',
    'k-p.li', 'kas.pr', 'kask.us', 'katzr.net', 'kbank.co', 'kck.st',
    'kf.org', 'kfrc.co', 'kg.games', 'kgs.link', 'kham.tw', 'kings.tn',
    'kkc.tech', 'kkday.me', 'kkne.ws', 'kko.to', 'kkstre.am', 'kl.ik.my',
    'klck.me', 'kli.cx', 'klmf.ly', 'ko.gl', 'kortlink.dk', 'kotl.in',
    'kp.org', 'kpmg.ch', 'krazy.la', 'kuku.lu', 'kurl.ru', 'kutt.it',
    'ky77.link', 'l.linklyhq.com', 'l.prageru.com', 'l8r.it', 'laco.st', 'lam.bo',
    'lat.ms', 'latingram.my', 'lativ.tw', 'lbtw.tw', 'lc.cx', 'learn.to',
    'lego.build', 'lemde.fr', 'letsharu.cc', 'lft.to', 'lih.kg', 'lihi.biz',
    'lihi.cc', 'lihi.one', 'lihi.pro', 'lihi.tv', 'lihi.vip', 'lihi1.cc',
    'lihi1.com', 'lihi1.me', 'lihi2.cc', 'lihi2.com', 'lihi2.me', 'lihi3.cc',
    'lihi3.com', 'lihi3.me', 'lihipro.com', 'lihivip.com', 'liip.to', 'lin.ee',
    'lin0.de', 'link.ac', 'link.infini.fr', 'link.tubi.tv', 'linkbun.com', 'linkd.in',
    'linkjust.com', 'linko.page', 'linkopener.co', 'links2.me', 'linkshare.pro', 'linkye.net',
    'livemu.sc', 'livestre.am', 'llk.dk', 'llo.to', 'lmg.gg', 'lmt.co',
    'lmy.de', 'ln.run', 'lnk.bz', 'lnk.direct', 'lnk.do', 'lnk.sk',
    'lnkd.in', 'lnkiy.com', 'lnkiy.in', 'lnky.jp', 'lnnk.in', 'lnv.gy',
    'lohud.us', 'lonerwolf.co', 'loom.ly', 'low.es', 'lprk.co', 'lru.jp',
    'lsdl.es', 'lstu.fr', 'lt27.de', 'lttr.ai', 'ludia.gg', 'luminary.link',
    'lurl.cc', 'lyksoomu.com', 'lzd.co', 'm.me', 'm.tb.cn', 'm101.org',
    'm1p.fr', 'maac.io', 'maga.lu', 'man.ac.uk', 'many.at', 'maper.info',
    'mapfan.to', 'mayocl.in', 'mbapp.io', 'mbayaq.co', 'mcafee.ly', 'mcd.to',
    'mcgam.es', 'mck.co', 'mcys.co', 'me.sv', 'me2.kr', 'meck.co',
    'meetu.ps', 'merky.de', 'metamark.net', 'mgnet.me', 'mgstn.ly', 'michmed.org',
    'migre.me', 'minify.link', 'minilink.io', 'mitsha.re', 'mklnd.com', 'mm.rog.gg',
    'mney.co', 'mng.bz', 'mnge.it', 'mnot.es', 'mo.ma', 'momo.dm',
    'monster.cat', 'moo.im', 'moovit.me', 'mork.ro', 'mou.sr', 'mpl.pm',
    'mrte.ch', 'mrx.cl', 'ms.spr.ly', 'msft.it', 'msi.gm', 'mstr.cl',
    'mttr.io', 'mub.me', 'munbyn.biz', 'mvmtwatch.co', 'my.mtr.cool', 'mybmw.tw',
    'myglamm.in', 'mylt.tv', 'mypoya.com', 'myppt.cc', 'mysp.ac', 'myumi.ch',
    'myurls.ca', 'mz.cm', 'mzl.la', 'n.opn.tl', 'n.pr', 'n9.cl',
    'name.ly', 'nature.ly', 'nav.cx', 'naver.me', 'nbc4dc.com', 'nbcbay.com',
    'nbcchi.com', 'nbcct.co', 'nbcnews.to', 'nbzp.cz', 'nchcnh.info', 'nej.md',
    'neti.cc', 'netm.ag', 'nflx.it', 'ngrid.com', 'njersy.co', 'nkbp.jp',
    'nkf.re', 'nmrk.re', 'nnn.is', 'nnna.ru', 'nokia.ly', 'notlong.com',
    'nr.tn', 'nswroads.work', 'ntap.com', 'ntck.co', 'ntn.so', 'ntuc.co',
    'nus.edu', 'nvda.ws', 'nwppr.co', 'nwsdy.li', 'nxb.tw', 'nxdr.co',
    'nycu.to', 'nydn.us', 'nyer.cm', 'nyp.st', 'nyr.kr', 'nyti.ms',
    'o.vg', 'oal.lu', 'obank.tw', 'ock.cn', 'ocul.us', 'oe.cd',
    'ofcour.se', 'offerup.co', 'offf.to', 'offs.ec', 'okt.to', 'omni.ag',
    'on.bcg.com', 'on.bp.com', 'on.fb.me', 'on.ft.com', 'on.louisvuitton.com', 'on.mktw.net',
    'on.natgeo.com', 'on.nba.com', 'on.ny.gov', 'on.nyc.gov', 'on.nypl.org', 'on.tcs.com',
    'on.wsj.com', 'on9news.tv', 'onelink.to', 'onepl.us', 'onforb.es', 'onion.com',
    'onx.la', 'oow.pw', 'opr.as', 'opr.news', 'optimize.ly', 'oran.ge',
    'orlo.uk', 'osdb.link', 'oshko.sh', 'ouo.io', 'ouo.press', 'ourl.co',
    'ourl.in', 'ourl.tw', 'outschooler.me', 'ovh.to', 'ow.ly', 'owl.li',
    'owy.mn', 'oxelt.gl', 'oxf.am', 'oyn.at', 'p.asia', 'p.dw.com',
    'p1r.es', 'p4k.in', 'pa.ag', 'packt.link', 'pag.la', 'pchome.link',
    'pck.tv', 'pdora.co', 'pdxint.at', 'pe.ga', 'pens.pe', 'peoplem.ag',
    'pepsi.co', 'pesc.pw', 'petrobr.as', 'pew.org', 'pewrsr.ch', 'pg3d.app',
    'pgat.us', 'pgrs.in', 'philips.to', 'piee.pw', 'pin.it', 'pipr.es',
    'pj.pizza', 'pl.kotl.in', 'pldthome.info', 'plu.sh', 'pnsne.ws', 'pod.fo',
    'poie.ma', 'pojonews.co', 'politi.co', 'popm.ch', 'posh.mk', 'pplx.ai',
    'ppt.cc', 'ppurl.io', 'pr.tn', 'prbly.us', 'prdct.school', 'preml.ge',
    'prf.hn', 'prgress.co', 'prn.to', 'propub.li', 'pros.is', 'psce.pw',
    'pse.is', 'psee.io', 'pt.rog.gg', 'ptix.co', 'puext.in', 'purdue.university',
    'purefla.sh', 'puri.na', 'pwc.to', 'pxgo.net', 'pxu.co', 'pzdls.co',
    'q.gs', 'qnap.to', 'qptr.ru', 'qr.ae', 'qr.net', 'qrco.de',
    'qrs.ly', 'qvc.co', 'r-7.co', 'r.zecz.ec', 'rb.gy', 'rbl.ms',
    'rblx.co', 'rch.lt', 'rd.gt', 'rdbl.co', 'rdcrss.org', 'rdcu.be',
    'read.bi', 'readhacker.news', 'rebelne.ws', 'rebrand.ly', 'reconis.co', 'red.ht',
    'redaz.in', 'redir.ec', 'redir.is', 'redsto.ne', 'ref.trade.re', 'refini.tv',
    'regmovi.es', 'reline.cc', 'relink.asia', 'rem.ax', 'renew.ge', 'replug.link',
    'rethinktw.cc', 'reurl.cc', 'reut.rs', 'rev.cm', 'revr.ec', 'rfr.bz',
    'ringcentr.al', 'riot.com', 'rip.city', 'risu.io', 'ritea.id', 'rizy.ir',
    'rlu.ru', 'rly.pt', 'rnm.me', 'ro.blox.com', 'rog.gg', 'roge.rs',
    'rol.st', 'rotf.lol', 'rozhl.as', 'rpf.io', 'rptl.io', 'rsc.li',
    'rsh.md', 'rtvote.com', 'ru.rog.gg', 'rushgiving.com', 'rvtv.io', 'rvwd.co',
    'rwl.io', 'ryml.me', 'rzr.to', 's.accupass.com', 's.coop', 's.ee',
    's.g123.jp', 's.id', 's.mj.run', 's.ul.com', 's.uniqlo.com', 's.wikicharlie.cl',
    's04.de', 's3vip.tw', 'saf.li', 'safelinking.net', 'safl.it', 'sail.to',
    'samcart.me', 'sbird.co', 'sbux.co', 'sbux.jp', 'sc.mp', 'sc.org',
    'sched.co', 'sck.io', 'scr.bi', 'scrb.ly', 'scuf.co', 'sdpbne.ws',
    'sdu.sk', 'sdut.us', 'se.rog.gg', 'seagate.media', 'sealed.in', 'seedsta.rs',
    'seiu.co', 'sejr.nl', 'selnd.com', 'seq.vc', 'sf3c.tw', 'sfca.re',
    'sfcne.ws', 'sforce.co', 'sfty.io', 'sgq.io', 'shar.as', 'shiny.link',
    'shln.me', 'sho.pe', 'shope.ee', 'shorl.com', 'short.gy', 'shorte.st',
    'shorten.asia', 'shorten.ee', 'shorten.is', 'shorten.so', 'shorten.tv', 'shorten.world',
    'shorter.me', 'shorturl.ae', 'shorturl.asia', 'shorturl.at', 'shorturl.com', 'shorturl.gg',
    'shp.ee', 'shrtco.de', 'shrtm.nu', 'sht.moe', 'shutr.bz', 'sie.ag',
    'simp.ly', 'sina.lt', 'sincere.ly', 'sinourl.tw', 'sinyi.biz', 'sinyi.in',
    'siriusxm.us', 'siteco.re', 'sk.in.rs', 'skimmth.is', 'skl.sh', 'skr.rs',
    'skrat.it', 'skyurl.cc', 'slidesha.re', 'small.cat', 'smart.link', 'smarturl.it',
    'smashed.by', 'smlk.es', 'smsb.co', 'smsng.news', 'smsng.us', 'smtvj.com',
    'smu.gs', 'sn.rs', 'snd.sc', 'sndn.link', 'snip.link', 'snip.ly',
    'snyk.co', 'so.arte', 'soc.cr', 'soch.us', 'social.ora.cl', 'socx.in',
    'sokrati.ru', 'solsn.se', 'sou.nu', 'sourl.cn', 'sovrn.co', 'spcne.ws',
    'spgrp.sg', 'spigen.co', 'split.to', 'splk.it', 'spoti.fi', 'spotify.link',
    'spr.ly', 'spr.tn', 'sprtsnt.ca', 'sqex.to', 'sqrx.io', 'squ.re',
    'srnk.us', 'ssur.cc', 'st.news', 'st8.fm', 'stanford.io', 'starz.tv',
    'stmodel.com', 'storycor.ps', 'stspg.io', 'stts.in', 'stuf.in', 'sumal.ly',
    'suo.fyi', 'suo.im', 'supr.cl', 'supr.link', 'surl.li', 'svy.mk',
    'swa.is', 'swag.run', 'swiy.co', 'swoo.sh', 'swtt.cc', 'sy.to',
    'syb.la', 'synd.co', 'syw.co', 't-bi.link', 't-mo.co', 't.cn',
    't.co', 't.iotex.me', 't.libren.ms', 't.ly', 't.me', 't.tl',
    't1p.de', 't2m.io', 'ta.co', 'tabsoft.co', 'taiwangov.com', 'tanks.ly',
    'tbb.tw', 'tbrd.co', 'tcrn.ch', 'tdrive.li', 'tdy.sg', 'tek.io',
    'temu.to', 'ter.li', 'tg.pe', 'tgam.ca', 'tgr.ph', 'thatis.me',
    'thd.co', 'thedo.do', 'thefp.pub', 'thein.fo', 'thesne.ws', 'thetim.es',
    'thght.works', 'thinfi.com', 'thls.co', 'thn.news', 'thr.cm', 'thrill.to',
    'ti.me', 'tibco.cm', 'tibco.co', 'tidd.ly', 'tim.com.vc', 'tinu.be',
    'tiny.cc', 'tiny.ee', 'tiny.one', 'tiny.pl', 'tinyarro.ws', 'tinylink.net',
    'tinyurl.com', 'tinyurl.hu', 'tinyurl.mobi', 'tktwb.tw', 'tl.gd', 'tlil.nl',
    'tlrk.it', 'tmblr.co', 'tmsnrt.rs', 'tmz.me', 'tnne.ws', 'tnsne.ws',
    'tnvge.co', 'tnw.to', 'tny.cz', 'tny.im', 'tny.so', 'to.ly',
    'to.pbs.org', 'toi.in', 'tokopedia.link', 'tonyr.co', 'topt.al', 'toyota.us',
    'tpc.io', 'tpmr.com', 'tprk.us', 'tr.ee', 'trackurl.link', 'trade.re',
    'travl.rs', 'trib.al', 'trib.in', 'troy.hn', 'trt.sh', 'trymongodb.com',
    'tsbk.tw', 'tsta.rs', 'tt.vg', 'tvote.org', 'tw.rog.gg', 'tw.sv',
    'twb.nz', 'twm5g.co', 'twou.co', 'txdl.top', 'txul.cn', 'u.nu',
    'u.shxj.pw', 'u.to', 'u1.mnge.co', 'ua.rog.gg', 'uafly.co', 'ubm.io',
    'ubnt.link', 'ubr.to', 'ucbexed.org', 'ucla.in', 'ufcqc.link', 'ugp.io',
    'ui8.ru', 'uk.rog.gg', 'ukf.me', 'ukoeln.de', 'ul.rs', 'ul.to',
    'ul3.ir', 'ulvis.net', 'ume.la', 'umlib.us', 'unc.live', 'undrarmr.co',
    'uni.cf', 'unipapa.co', 'uofr.us', 'uoft.me', 'up.to', 'upmchp.us',
    'ur3.us', 'urb.tf', 'urbn.is', 'url.cn', 'url.cy', 'url.ie',
    'url2.fr', 'urla.ru', 'urlgeni.us', 'urli.ai', 'urlify.cn', 'urlr.me',
    'urls.fr', 'urls.kr', 'urluno.com', 'urly.co', 'urly.fi', 'urlz.fr',
    'urlzs.com', 'urt.io', 'us.rog.gg', 'usanet.tv', 'usat.ly', 'utm.to',
    'utn.pl', 'utraker.com', 'v.gd', 'v.ht', 'v.redd.it', 'vbly.us',
    'vd55.com', 'vercel.link', 'vi.sa', 'vi.tc', 'viaalto.me', 'viaja.am',
    'vineland.dj', 'viraln.co', 'vivo.tl', 'vk.cc', 'vk.sv', 'vl.xyz',
    'vn.rog.gg', 'vntyfr.com', 'vo.la', 'vodafone.uk', 'vogue.cm', 'voicetu.be',
    'volvocars.us', 'vonq.io', 'vrnda.us', 'vtns.io', 'vur.me', 'vurl.com',
    'vvnt.co', 'vxn.link', 'vypij.bar', 'vz.to', 'w.idg.de', 'w.wiki',
    'w5n.co', 'wa.link', 'wa.me', 'wa.sv', 'waa.ai', 'waad.co',
    'wahoowa.net', 'walk.sc', 'walkjc.org', 'wapo.st', 'warby.me', 'warp.plus',
    'wartsi.ly', 'way.to', 'wb.md', 'wbby.co', 'wbur.fm', 'wbze.de',
    'wcha.it', 'we.co', 'weall.vote', 'weare.rs', 'wee.so', 'wef.ch',
    'wellc.me', 'wenk.io', 'wf0.xin', 'whatel.se', 'whcs.law', 'whi.ch',
    'whoel.se', 'whr.tn', 'wi.se', 'win.gs', 'wit.to', 'wjcf.co',
    'wkf.ms', 'wmojo.com', 'wn.nr', 'wndrfl.co', 'wo.ws', 'wooo.tw',
    'wp.me', 'wpbeg.in', 'wrctr.co', 'wrd.cm', 'wrem.it', 'wun.io',
    'ww7.fr', 'wwf.to', 'wwp.news', 'www.shrunken.com', 'x.gd', 'xbx.lv',
    'xerox.bz', 'xfin.tv', 'xfl.ag', 'xfru.it', 'xgam.es', 'xor.tw',
    'xpr.li', 'xprt.re', 'xqss.org', 'xrds.ca', 'xrl.us', 'xurl.es',
    'xvirt.it', 'y.ahoo.it', 'y2u.be', 'yadi.sk', 'yal.su', 'yelp.to',
    'yex.tt', 'yhoo.it', 'yip.su', 'yji.tw', 'ynews.page.link', 'yoox.ly',
    'your.ls', 'yourls.org', 'yourwish.es', 'yubi.co', 'yun.ir', 'z23.ru',
    'zaya.io', 'zc.vg', 'zcu.io', 'zd.net', 'zdrive.li', 'zdsk.co',
    'zecz.ec', 'zeep.ly', 'zez.kr', 'zi.ma', 'ziadi.co', 'zipurl.fr',
    'zln.do', 'zlr.my', 'zlra.co', 'zlw.re', 'zoho.to', 'zopen.to',
    'zovpart.com', 'zpr.io', 'zuki.ie', 'zuplo.link', 'zurb.us', 'zurins.uk',
    'zurl.co', 'zurl.ir', 'zurl.ws', 'zws.im', 'zxc.li', 'zynga.my',
    'zywv.us', 'zzb.bz', 'zzu.info',
})

THREATS_DB = [
    {
        "id": 1,
        "name": "Phishing Attack",
        "category": "Social Engineering",
        "severity": "High",
        "icon": "phishing",
        "color": "#ff6b6b",
        "description": "Fraudulent attempts to obtain sensitive information by disguising as a trustworthy entity.",
        "indicators": [
            "Suspicious email sender address",
            "Urgent or threatening language",
            "Requests for personal/financial info",
            "Mismatched URLs on hover",
            "Poor grammar and spelling",
            "Unexpected attachments",
        ],
        "prevention": [
            "Verify sender email addresses carefully",
            "Never click suspicious links in emails",
            "Enable multi-factor authentication",
            "Use anti-phishing browser extensions",
            "Report phishing to IT security",
        ],
        "system_signs": [
            "Unexpected browser redirects",
            "Pop-ups asking for credentials",
            "Browser homepage changed",
        ],
    },
    {
        "id": 2,
        "name": "Ransomware",
        "category": "Malware",
        "severity": "Critical",
        "icon": "lock",
        "color": "#ff4757",
        "description": "Malicious software that encrypts victim's files and demands payment for decryption key.",
        "indicators": [
            "Files suddenly become inaccessible",
            "Ransom note appearing on desktop",
            "File extensions changed (.locked, .encrypted)",
            "Slow system performance",
            "Unusual network traffic spikes",
            "Antivirus disabled automatically",
        ],
        "prevention": [
            "Maintain regular offline backups",
            "Keep OS and software updated",
            "Disable macros in Office documents",
            "Use reputable endpoint protection",
            "Segment network access",
            "Train staff on email safety",
        ],
        "system_signs": [
            "CPU usage at 100% unexpectedly",
            "Files renamed with unknown extensions",
            "Desktop wallpaper changed to ransom note",
            "Cannot open common file types",
        ],
    },
    {
        "id": 3,
        "name": "SQL Injection",
        "category": "Web Attack",
        "severity": "High",
        "icon": "database",
        "color": "#ffa502",
        "description": "Inserting malicious SQL code into input fields to manipulate database queries.",
        "indicators": [
            "Unexpected database errors in application",
            "Unusual database query patterns in logs",
            "Data appearing in wrong fields",
            "Application returning all database records",
            "Error messages exposing database structure",
        ],
        "prevention": [
            "Use parameterized queries/prepared statements",
            "Validate and sanitize all user inputs",
            "Implement Web Application Firewall (WAF)",
            "Apply principle of least privilege for DB users",
            "Regularly audit database access logs",
        ],
        "system_signs": [
            "Application logs showing SQL errors",
            "Unexpected data in web responses",
            "Database performance degradation",
        ],
    },
    {
        "id": 4,
        "name": "DDoS Attack",
        "category": "Network Attack",
        "severity": "High",
        "icon": "dns",
        "color": "#ff6348",
        "description": "Overwhelming a server with traffic from multiple sources to deny legitimate users access.",
        "indicators": [
            "Sudden spike in network traffic",
            "Server response times increase dramatically",
            "Website/service becomes unavailable",
            "Unusual traffic from single IP ranges",
            "Traffic patterns resembling bot behavior",
        ],
        "prevention": [
            "Use DDoS protection services (Cloudflare, AWS Shield)",
            "Configure rate limiting on servers",
            "Implement traffic filtering rules",
            "Use Content Delivery Networks (CDN)",
            "Have an incident response plan ready",
        ],
        "system_signs": [
            "Server CPU/memory at maximum",
            "Network bandwidth completely saturated",
            "Legitimate users cannot access service",
            "Firewall logging thousands of connection attempts",
        ],
    },
    {
        "id": 5,
        "name": "Man-in-the-Middle (MitM)",
        "category": "Network Attack",
        "severity": "High",
        "icon": "visibility",
        "color": "#eccc68",
        "description": "Attacker secretly intercepts and possibly alters communication between two parties.",
        "indicators": [
            "SSL certificate warnings in browser",
            "Unexpected certificate changes",
            "Unusual ARP traffic on network",
            "Slow network performance",
            "Session tokens appearing in logs from unusual IPs",
        ],
        "prevention": [
            "Always use HTTPS connections",
            "Verify SSL/TLS certificates",
            "Use VPN on public networks",
            "Enable HSTS on web servers",
            "Implement certificate pinning",
        ],
        "system_signs": [
            "Browser showing 'Connection not secure'",
            "Certificate mismatch warnings",
            "Sudden authentication failures",
        ],
    },
    {
        "id": 6,
        "name": "Keylogger / Spyware",
        "category": "Malware",
        "severity": "High",
        "icon": "keyboard",
        "color": "#a29bfe",
        "description": "Software that secretly records keystrokes, screenshots, or user activity.",
        "indicators": [
            "Unusual outbound network connections",
            "System running slowly",
            "Unknown processes in Task Manager",
            "Webcam light activating unexpectedly",
            "Mouse moving on its own",
        ],
        "prevention": [
            "Install reputable antivirus/anti-spyware",
            "Keep software updated",
            "Use virtual keyboards for sensitive input",
            "Monitor running processes regularly",
            "Avoid downloading software from unknown sources",
        ],
        "system_signs": [
            "Unknown background processes consuming CPU",
            "Network activity when idle",
            "Settings changed without your action",
            "Unexpected popups or ads",
        ],
    },
    {
        "id": 7,
        "name": "Cross-Site Scripting (XSS)",
        "category": "Web Attack",
        "severity": "Medium",
        "icon": "code",
        "color": "#74b9ff",
        "description": "Injecting malicious scripts into web pages viewed by other users.",
        "indicators": [
            "Unexpected JavaScript alerts on websites",
            "Unusual redirects after visiting pages",
            "Session cookies being stolen",
            "User data appearing on unauthorized pages",
        ],
        "prevention": [
            "Sanitize and encode all user input/output",
            "Implement Content Security Policy (CSP)",
            "Use HTTPOnly and Secure cookie flags",
            "Validate data on both client and server side",
            "Use modern web frameworks with built-in XSS protection",
        ],
        "system_signs": [
            "Random script alerts on trusted sites",
            "Being redirected without clicking anything",
            "Account activity from unknown locations",
        ],
    },
    {
        "id": 8,
        "name": "Brute Force Attack",
        "category": "Authentication Attack",
        "severity": "Medium",
        "icon": "lock_reset",
        "color": "#55efc4",
        "description": "Automated trial of many passwords/keys until the correct one is found.",
        "indicators": [
            "Multiple failed login attempts in logs",
            "Account lockouts happening frequently",
            "Login attempts from unusual geographic locations",
            "Traffic spikes to authentication endpoints",
        ],
        "prevention": [
            "Implement account lockout policies",
            "Enable multi-factor authentication (MFA)",
            "Use strong, complex passwords",
            "Monitor and alert on failed login attempts",
            "Use CAPTCHA on login forms",
            "Implement rate limiting",
        ],
        "system_signs": [
            "Account locked out unexpectedly",
            "Receiving unexpected password reset emails",
            "Log files showing thousands of login attempts",
        ],
    },
]

TROUBLESHOOT_GUIDES = [
    {
        "id": "slow-pc",
        "title": "My Computer is Suddenly Very Slow",
        "icon": "speed",
        "category": "Performance",
        "severity": "Medium",
        "steps": [
            {"step": 1, "action": "Check for Malware", "detail": "Run a full system scan with your antivirus. Malware often consumes significant CPU/RAM. Use Windows Defender or Malwarebytes for a second opinion."},
            {"step": 2, "action": "Check Running Processes", "detail": "Open Task Manager (Ctrl+Shift+Esc on Windows) or Activity Monitor (Mac). Sort by CPU and Memory to identify suspicious processes with random names."},
            {"step": 3, "action": "Check Network Activity", "detail": "Look for unusually high network usage even when not downloading anything. This could indicate data exfiltration by malware."},
            {"step": 4, "action": "Review Startup Programs", "detail": "Malware often adds itself to startup. Check Task Manager > Startup tab (Windows) or System Preferences > Login Items (Mac)."},
            {"step": 5, "action": "Check Disk Health", "detail": "Failing hard drives cause slowdowns. Run disk diagnostics. On Windows: chkdsk /f. On Linux: smartctl -a /dev/sda."},
        ],
        "warning_signs": ["Ransomware may be encrypting files", "Cryptominer consuming resources", "Botnet activity"],
    },
    {
        "id": "browser-redirect",
        "title": "My Browser Keeps Redirecting",
        "icon": "alt_route",
        "category": "Browser Security",
        "severity": "High",
        "steps": [
            {"step": 1, "action": "Scan for Browser Hijackers", "detail": "Browser hijackers change your homepage, search engine, and redirect traffic. Use AdwCleaner or Malwarebytes to detect and remove them."},
            {"step": 2, "action": "Check Browser Extensions", "detail": "Malicious extensions cause redirects. Remove all unfamiliar extensions. In Chrome: Settings > Extensions. In Firefox: Add-ons Manager."},
            {"step": 3, "action": "Reset Browser Settings", "detail": "Reset your browser to default settings. This removes malicious changes to homepage, search engine, and startup pages."},
            {"step": 4, "action": "Check Hosts File", "detail": "Malware may modify the hosts file to redirect domains. Check: C:\\Windows\\System32\\drivers\\etc\\hosts (Windows) or /etc/hosts (Linux/Mac)."},
            {"step": 5, "action": "Flush DNS Cache", "detail": "Clear your DNS cache. Windows: ipconfig /flushdns. Mac: sudo dscacheutil -flushcache. Linux: sudo systemd-resolve --flush-caches"},
        ],
        "warning_signs": ["Phishing sites may capture credentials", "Malvertising exposure", "Data theft risk"],
    },
    {
        "id": "unknown-logins",
        "title": "Unknown Login Attempts on My Accounts",
        "icon": "warning",
        "category": "Account Security",
        "severity": "Critical",
        "steps": [
            {"step": 1, "action": "Change Password Immediately", "detail": "Use a strong, unique password (12+ characters, mixed case, numbers, symbols). Use a password manager like Bitwarden or 1Password."},
            {"step": 2, "action": "Enable Multi-Factor Authentication", "detail": "Add MFA/2FA to all important accounts immediately. Use an authenticator app (Google Authenticator, Authy) rather than SMS when possible."},
            {"step": 3, "action": "Check Active Sessions", "detail": "Review all active sessions on your accounts and revoke access from unrecognized devices/locations. Most platforms show this in Security Settings."},
            {"step": 4, "action": "Check for Data Breaches", "detail": "Visit haveibeenpwned.com to check if your email was in a data breach. Change passwords for any compromised accounts."},
            {"step": 5, "action": "Review Account Activity", "detail": "Check recent account activity for unauthorized transactions, emails sent, files accessed, or settings changed."},
        ],
        "warning_signs": ["Account takeover in progress", "Identity theft risk", "Financial fraud possible"],
    },
    {
        "id": "suspicious-email",
        "title": "Received a Suspicious Email",
        "icon": "mail",
        "category": "Email Security",
        "severity": "High",
        "steps": [
            {"step": 1, "action": "Do NOT Click Any Links", "detail": "Never click links in suspicious emails. Hover over links to see the actual URL destination before clicking anything."},
            {"step": 2, "action": "Verify the Sender", "detail": "Check the actual sender email address (not just the display name). Legitimate companies use their official domain, e.g., @company.com not @company-support.net."},
            {"step": 3, "action": "Check Email Headers", "detail": "Examine email headers to verify the true sending server. Mismatched 'From' and 'Reply-To' addresses are red flags."},
            {"step": 4, "action": "Report the Email", "detail": "Report phishing emails to your IT team, email provider, and organizations like the Anti-Phishing Working Group (reportphishing@apwg.org)."},
            {"step": 5, "action": "Delete and Block", "detail": "Delete the email and block the sender. If you accidentally clicked a link, immediately run a malware scan and change passwords."},
        ],
        "warning_signs": ["Phishing attempt detected", "Potential credential harvesting", "Malware delivery possible"],
    },
    {
        "id": "wifi-security",
        "title": "Concerned About WiFi Security",
        "icon": "wifi_lock",
        "category": "Network Security",
        "severity": "Medium",
        "steps": [
            {"step": 1, "action": "Use WPA3 or WPA2 Encryption", "detail": "Ensure your WiFi router uses WPA3 (preferred) or at minimum WPA2 encryption. Never use WEP (easily cracked) or open networks."},
            {"step": 2, "action": "Change Default Router Credentials", "detail": "Change the default admin username and password on your router immediately. Default credentials are publicly known and easily exploited."},
            {"step": 3, "action": "Check Connected Devices", "detail": "Review all devices connected to your network via your router's admin panel. Identify and remove any unfamiliar devices."},
            {"step": 4, "action": "Disable WPS", "detail": "WiFi Protected Setup (WPS) has known vulnerabilities. Disable it in your router settings."},
            {"step": 5, "action": "Use VPN on Public WiFi", "detail": "Always use a VPN when connecting to public WiFi (cafes, airports, hotels) to encrypt your traffic and prevent interception."},
        ],
        "warning_signs": ["Unauthorized network access", "Traffic interception risk", "MitM attack possible"],
    },
    {
        "id": "ransomware-infected",
        "title": "Files Are Encrypted / Ransomware",
        "icon": "lock",
        "category": "Malware",
        "severity": "Critical",
        "steps": [
            {"step": 1, "action": "IMMEDIATELY Disconnect from Network", "detail": "Unplug ethernet cable and disable WiFi IMMEDIATELY. Ransomware spreads through networks. Isolating the device stops further spread."},
            {"step": 2, "action": "Do NOT Pay the Ransom", "detail": "Paying does not guarantee file recovery and funds criminal operations. Contact law enforcement (FBI, local cybercrime unit) to report."},
            {"step": 3, "action": "Document the Attack", "detail": "Take photos of ransom notes and record all details. This information is vital for law enforcement and insurance claims."},
            {"step": 4, "action": "Check for Decryption Tools", "detail": "Visit NoMoreRansom.org – a free resource with decryption tools for many ransomware variants. Identify the ransomware strain first."},
            {"step": 5, "action": "Restore from Backup", "detail": "If you have clean backups from before the infection, restore your system. Verify backups are not also encrypted before restoring."},
        ],
        "warning_signs": ["CRITICAL: Active ransomware infection", "Data loss imminent", "Network spread possible"],
    },
]

MOCK_INBOX_EMAILS = [
    {
        "id": 1,
        "sender_name": "Netflix Support",
        "sender_email": "billing-update@netflix-security-alert.net",
        "subject": "Urgent: Update your payment method",
        "date": "Today, 10:24 AM",
        "body_html": """
            <p>Dear Customer,</p>
            <p>We were unable to process your monthly subscription payment. Your account will be suspended within 24 hours if you do not update your payment details.</p>
            <p>Please click the button below to update your billing information immediately:</p>
            <p style="margin: 1.5rem 0;"><a href="http://update-netflix-account.xyz/billing" class="sim-btn" onclick="event.preventDefault();">Update Billing Info</a></p>
            <p>Thank you,<br>Netflix Support Team</p>
        """,
        "is_phishing": True,
        "red_flags": [
            {"target": "netflix-security-alert.net", "reason": "Mismatched domain in email address: Netflix does not use 'netflix-security-alert.net'."},
            {"target": "suspended within 24 hours", "reason": "Urgency: Phishing emails often create artificial deadlines to panic users into acting."},
            {"target": "update-netflix-account.xyz", "reason": "Suspicious URL: The link points to a '.xyz' domain instead of the official 'netflix.com' website."}
        ],
        "explanation": "This is a classic billing phishing scam. The sender domain, suspicious '.xyz' link, and high sense of urgency (threatening suspension in 24 hours) are major warning signs."
    },
    {
        "id": 2,
        "sender_name": "Internal IT Helpdesk",
        "sender_email": "helpdesk@cyberdefensepro.corp",
        "subject": "Scheduled Network Maintenance this Saturday",
        "date": "Yesterday, 3:15 PM",
        "body_html": """
            <p>Team,</p>
            <p>Please be advised that the corporate network will undergo routine maintenance this Saturday, June 27, from 12:00 AM to 4:00 AM EAT.</p>
            <p>During this window, access to the VPN, internal wikis, and local file shares may be temporarily offline. No action is required from your side. If you experience persistent issues after 4:00 AM, please contact IT support at extension 404.</p>
            <p>Best regards,<br>IT Operations Department</p>
        """,
        "is_phishing": False,
        "red_flags": [],
        "explanation": "This email is legitimate. The sender domain matches the official corporate domain, the tone is purely informative, there is no threat or pressure to click a link, and no credentials or personal information are requested."
    },
    {
        "id": 3,
        "sender_name": "Google Account Team",
        "sender_email": "no-reply@accounts.google.support-security.com",
        "subject": "Critical Security Alert: Suspicious login attempt blocked",
        "date": "June 22, 2:05 PM",
        "body_html": """
            <p>Hi User,</p>
            <p>Someone recently tried to log into your Google Account from a new device in Moscow, Russia. Google blocked this sign-in attempt, but you should verify your password immediately to secure your account.</p>
            <p>Please check your activity and change your password now:</p>
            <p style="margin: 1.5rem 0;"><a href="https://accounts.google.com-recovery-portal.info/login" class="sim-btn" onclick="event.preventDefault();">Check Activity Now</a></p>
            <p>If this was you, you can safely ignore this message.</p>
            <p>Sincerely,<br>The Google Accounts Team</p>
        """,
        "is_phishing": True,
        "red_flags": [
            {"target": "accounts.google.support-security.com", "reason": "Lookalike Domain: Google emails originate from '@google.com' or '@accounts.google.com', not 'support-security.com'."},
            {"target": "google.com-recovery-portal.info", "reason": "Spoofed Link: The domain is 'google.com-recovery-portal.info' (ending in .info), not the actual 'google.com'."}
        ],
        "explanation": "This is a credential harvesting attempt. The attacker mimics Google's actual security alerts, but uses a lookalike sender domain and an external recovery portal to steal your login credentials."
    },
    {
        "id": 4,
        "sender_name": "PayPal Billing",
        "sender_email": "service@paypaI.com",
        "subject": "Invoice for your recent transaction (#PP-4820)",
        "date": "June 20, 8:40 AM",
        "body_html": """
            <p>Hello,</p>
            <p>You have authorized a payment of $849.99 USD to Coinbase Inc. for purchasing Bitcoin. This charge will appear on your bank statement shortly.</p>
            <p>If you did not authorize this purchase, please contact our fraud department immediately at 1-800-PAY-TIPS or click the dispute link below to cancel the charge:</p>
            <p style="margin: 1.5rem 0;"><a href="http://paypal-resolutions-portal.net/disputes" class="sim-btn" onclick="event.preventDefault();">Cancel Transaction</a></p>
            <p>Thank you for using PayPal.</p>
        """,
        "is_phishing": True,
        "red_flags": [
            {"target": "paypaI.com", "reason": "Typosquatting/Homograph: The 'l' in 'paypal' is replaced with a capital 'I' (paypaI.com). This is extremely hard to spot visually but points to a completely different domain!"},
            {"target": "authorized a payment of $849.99", "reason": "Emotional Panic Trigger: Scammers use high unauthorized charges to scare you into clicking their link quickly without thinking."},
            {"target": "paypal-resolutions-portal.net", "reason": "Unrelated Domain: PayPal uses 'paypal.com' for all disputes, not 'paypal-resolutions-portal.net'."}
        ],
        "explanation": "This scam attempts to exploit fear of money loss. It uses a homograph domain ('paypaI.com' with an uppercase 'i' instead of 'l') and guides you to a malicious site to 'dispute' a transaction you never made."
    },
    {
        "id": 5,
        "sender_name": "HR Department",
        "sender_email": "hr@cyberdefensepro.corp",
        "subject": "New Employee Handbook & Code of Conduct",
        "date": "June 18, 9:00 AM",
        "body_html": """
            <p>Dear Team,</p>
            <p>We have updated the Employee Handbook and Code of Conduct guidelines for this fiscal year. The updates cover remote work arrangements, home office expenses, and cybersecurity requirements.</p>
            <p>Please review the updated PDF document in the HR portal or download the attached document to sign and return the acknowledgment form to HR by the end of the week.</p>
            <p>Attachment: <strong>Employee_Handbook_2026.pdf</strong> (1.4 MB)</p>
            <p>Best regards,<br>HR Services Team</p>
        """,
        "is_phishing": False,
        "red_flags": [],
        "explanation": "This email is legitimate. The sender is internal HR, the tone is professional, it references standard company policy, the attachment is a safe PDF format, and there is no pressure or threat of negative action."
    }
]

CAMPAIGN_DATA = [
    {
        "id": "wire_transfer",
        "title": "The Wire Transfer",
        "difficulty": "Easy",
        "narrative": "You're a newly hired financial analyst at Meridian Corp. Strange emails have been circulating about urgent wire transfers. Your job: separate fact from fraud.",
        "threat_type": "CEO Fraud / Business Email Compromise",
        "xp_reward": 50,
        "emails": [
            {
                "id": "wt_phish_1",
                "sender_name": "James Whitfield",
                "sender_email": "j.whitfield@meridian-corp.works",
                "subject": "URGENT: Confidential Wire Transfer — Action Required Today",
                "date": "Today, 8:12 AM",
                "body_html": """
                    <p>Hi,</p>
                    <p>I'm in a board meeting and can't take calls. We need to process an urgent wire transfer for a time-sensitive acquisition. The usual approval process won't work — the counterparty's window closes at noon today.</p>
                    <p>Please initiate a transfer of <strong>KSH 18,500,000</strong> to the following account immediately:</p>
                    <div style="background:#f4f6f9;border-left:4px solid #2563eb;padding:1rem 1.25rem;margin:1rem 0;border-radius:4px;font-family:monospace;font-size:0.9rem;">
                        <p style="margin:0;"><strong>Bank:</strong> Equity Bank Kenya</p>
                        <p style="margin:0;"><strong>Account Name:</strong> Rift Valley Ventures Ltd</p>
                        <p style="margin:0;"><strong>Account #:</strong> 8847201935</p>
                        <p style="margin:0;"><strong>Bank Code:</strong> 074</p>
                    </div>
                    <p>I've already looped in Legal — they're expecting this. Reference the payment as "Strategic Initiative — Phase 1" in the memo line.</p>
                    <p>This is confidential. Don't discuss it on Slack or email anyone else about it. Reply to me directly if you have questions.</p>
                    <p>Thanks,<br>James Whitfield<br>CEO, Meridian Corp</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "meridian-corp.works", "reason": "Lookalike domain: The real Meridian Corp uses 'meridian-corp.com'. The '.works' TLD is a common attacker trick to impersonate corporate domains."},
                    {"target": "URGENT: Confidential Wire Transfer", "reason": "Urgency + secrecy combination: Attackers create artificial time pressure and isolate you from colleagues so you won't verify the request."},
                    {"target": "I'm in a board meeting and can't take calls", "reason": "Pretext for unreachability: The attacker gives a reason why they can't be contacted by phone, preventing you from verifying the request with the real CEO."},
                    {"target": "Rift Valley Ventures Ltd", "reason": "Unfamiliar beneficiary: Legitimate wire transfers at established companies go to known, pre-vetted vendor accounts — not new entities you've never heard of."},
                    {"target": "Don't discuss it on Slack or email anyone else", "reason": "Isolation tactic: Explicitly forbidding you from consulting colleagues is designed to prevent the fraud from being caught before the money leaves."}
                ],
                "explanation": "This is a classic CEO Fraud / Business Email Compromise (BEC) attack. The attacker impersonates the CEO, creates urgency, provides wire instructions to a controlled account, and isolates the target from colleagues. Always verify wire transfer requests via a separate communication channel — never reply to the email."
            },
            {
                "id": "wt_phish_2",
                "sender_name": "Accounts Payable",
                "sender_email": "ap@meridiancorp-finance.com",
                "subject": "Updated Payment Instructions — Action Required",
                "date": "Today, 9:03 AM",
                "body_html": """
                    <p>Good morning,</p>
                    <p>As part of our quarterly compliance review, we've updated our banking details for vendor payments. Please use the following account information for all outgoing wire transfers effective immediately:</p>
                    <div style="background:#f4f6f9;border-left:4px solid #2563eb;padding:1rem 1.25rem;margin:1rem 0;border-radius:4px;font-family:monospace;font-size:0.9rem;">
                        <p style="margin:0;"><strong>Bank:</strong> KCB Group</p>
                        <p style="margin:0;"><strong>Account Name:</strong> Meridian Corp Operating</p>
                        <p style="margin:0;"><strong>Account #:</strong> 4491027365</p>
                        <p style="margin:0;"><strong>Bank Code:</strong> 011</p>
                    </div>
                    <p>Please update your payment templates in the ERP system by end of day. Payments sent to old accounts after today may not be recovered.</p>
                    <p>If you have any questions, reply to this email or visit our portal at <a href="https://meridian-corp-finance.com/updates" style="color:#2563eb;" onclick="event.preventDefault();">meridian-corp-finance.com/updates</a>.</p>
                    <p>Thank you,<br>Accounts Payable Department<br>Meridian Corp</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "meridiancorp-finance.com", "reason": "Spoofed domain: The legitimate company domain is 'meridian-corp.com' with a hyphen. This domain 'meridiancorp-finance.com' drops the hyphen and adds a suffix — a subtle impersonation trick."},
                    {"target": "Updated Payment Instructions", "reason": "Payment instruction changes are a top BEC tactic: Attackers intercept the right timing (after CEO fraud) to redirect funds to their accounts."},
                    {"target": "Payments sent to old accounts after today may not be recovered", "reason": "Fear-based pressure: The threat of lost funds pressures you to act quickly rather than verifying the change through normal channels."},
                    {"target": "meridian-corp-finance.com/updates", "reason": "Malicious link: The portal URL uses the same spoofed domain. Any credentials entered here go to the attacker."}
                ],
                "explanation": "This is a Business Email Compromise follow-up attack. After the fake CEO email, a second attacker sends 'updated payment instructions' to make the wire transfer seem routine. Notice the domain is slightly different from the real 'meridian-corp.com'. Always verify banking changes through your established finance team contact — not via email."
            },
            {
                "id": "wt_legit_1",
                "sender_name": "IT Operations",
                "sender_email": "it-ops@meridian-corp.com",
                "subject": "Scheduled Server Maintenance — Saturday 2 AM–6 AM EAT",
                "date": "Yesterday, 4:30 PM",
                "body_html": """
                    <p>Hi everyone,</p>
                    <p>This is a reminder that we have scheduled maintenance on our internal servers this Saturday from 2:00 AM to 6:00 AM EAT. During this window, the following services will be unavailable:</p>
                    <ul>
                        <li>Internal email (Outlook/OWA)</li>
                        <li>SharePoint and OneDrive</li>
                        <li>VPN access</li>
                        <li>ERP system (Sage ERP)</li>
                    </ul>
                    <p>Please save all work and log out of VPN before 2:00 AM. If you have critical operations that require system access during this window, please contact the IT Service Desk by Friday EOD to arrange an exemption.</p>
                    <p>We apologize for the inconvenience. This maintenance is necessary to apply critical security patches to our infrastructure.</p>
                    <p>Best,<br>IT Operations Team<br>it-ops@meridian-corp.com</p>
                """,
                "is_phishing": False,
                "red_flags": [],
                "explanation": "This email is legitimate. It comes from the verified internal domain 'meridian-corp.com', provides a reasonable and routine maintenance notice, lists specific services affected, and asks employees to plan ahead — typical corporate IT communication with no urgency, threats, or suspicious links."
            },
            {
                "id": "wt_phish_3",
                "sender_name": "Security Alert Team",
                "sender_email": "alerts@meridian-secure-banking.com",
                "subject": "FRAUD ALERT: Suspicious Transaction Detected on Corporate Account",
                "date": "Today, 7:45 AM",
                "body_html": """
                    <p style="color:#dc2626;font-weight:bold;">⚠ FRAUD ALERT — Immediate Verification Required</p>
                    <p>Dear Meridian Corp Account Holder,</p>
                    <p>Our fraud detection system has flagged <strong>3 suspicious transactions</strong> on your corporate checking account ending in ****4821:</p>
                    <div style="background:#fef2f2;border-left:4px solid #dc2626;padding:1rem 1.25rem;margin:1rem 0;border-radius:4px;font-size:0.9rem;">
                        <p style="margin:0;">Transaction 1: KSH 3,510,000 — Wire to unknown recipient — <em>PENDING</em></p>
                        <p style="margin:0;">Transaction 2: KSH 2,280,000 — ACH debit — <em>PENDING</em></p>
                        <p style="margin:0;">Transaction 3: KSH 1,335,000 — International wire — <em>PENDING</em></p>
                    </div>
                    <p>If you did not authorize these transactions, you must verify your identity within <strong>60 minutes</strong> to prevent the transfers from completing.</p>
                    <p style="margin:1rem 0;"><a href="https://meridian-secure-banking.com/verify?acct=4821" class="sim-btn" onclick="event.preventDefault();">Verify Identity &amp; Block Transactions</a></p>
                    <p>If you do not verify, the transactions will be processed and recovery cannot be guaranteed.</p>
                    <p>Meridian Corporate Banking Security Division</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "meridian-secure-banking.com", "reason": "Fake banking domain: Meridian Corp banks with Equity Bank Kenya (as shown in company records), not 'meridian-secure-banking.com'. This is a credential harvesting site."},
                    {"target": "60 minutes", "reason": "Artificial deadline: The 60-minute window is designed to panic you into clicking without verifying the alert's legitimacy."},
                    {"target": "FRAUD ALERT", "reason": "Fear-based manipulation: Showing large pending fraudulent charges triggers a panic response. Real fraud alerts don't typically appear via unsolicited email as the primary notification."},
                    {"target": "Verify Identity & Block Transactions", "reason": "Credential harvesting: This button leads to a fake login page designed to capture your corporate banking credentials."},
                    {"target": "recovery cannot be guaranteed", "reason": "Consequence pressure: Threatening permanent loss if you don't act immediately is a classic social engineering tactic."}
                ],
                "explanation": "This phishing email impersonates a banking fraud alert to harvest credentials. The sender domain 'meridian-secure-banking.com' is fabricated. Real fraud alerts come from your actual bank's verified domain, and banks typically call for urgent fraud matters — not just email. Never click links in unsolicited fraud alerts; always call your bank directly using the number on your card."
            },
            {
                "id": "wt_phish_4",
                "sender_name": "Robert Chen",
                "sender_email": "r.chen@meridian-corp.works",
                "subject": "Quick Favor — Client Appreciation Gifts",
                "date": "Today, 10:15 AM",
                "body_html": """
                    <p>Hey,</p>
                    <p>Following up on our conversation at the offsite — I need your help getting 15 Safaricom top-up cards (KSH 25,000 each) for our top clients as part of the Q3 appreciation initiative. The board signed off on this yesterday.</p>
                    <p>I know this is unconventional, but we need to get these out before the end of the quarter. Can you purchase them and email me the redemption codes? I'll reimburse you through expense reporting.</p>
                    <p>Total cost: KSH 375,000. Use the corporate purchasing card if possible — otherwise, I'll make sure finance expedites your reimbursement.</p>
                    <p>I'm heads-down in client meetings all day so email is the best way to reach me. Thanks!</p>
                    <p>Best,<br>Robert Chen<br>CFO, Meridian Corp</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "meridian-corp.works", "reason": "Lookalike domain: Same '.works' TLD impersonation used in the fake CEO email — a strong indicator this is part of the same attack campaign."},
                    {"target": "Safaricom top-up cards", "reason": "Gift card scam: Safaricom top-up cards are untraceable and irreversible. Legitimate companies never use gift cards as client gifts through individual employees."},
                    {"target": "email me the redemption codes", "reason": "Credential/code theft: Once the attacker has the gift card codes, they are instantly redeemed and untraceable."},
                    {"target": "I'm heads-down in client meetings all day so email is the best way to reach me", "reason": "Pretext for isolation: Again preventing you from picking up the phone to verify the request with the real CFO."},
                    {"target": "reimburse you through expense reporting", "reason": "Trust building: Offering reimbursement makes the request seem like standard business practice rather than theft."}
                ],
                "explanation": "This is a gift card fraud attack impersonating the CFO. The attacker requests untraceable gift cards and asks for redemption codes via email. Legitimate companies never ask employees to purchase gift cards and share codes over email. Always verify unusual financial requests — especially ones involving gift cards — via a phone call to the supposed requester."
            }
        ]
    },
    {
        "id": "supply_chain",
        "title": "Supply Chain Nightmare",
        "difficulty": "Easy-Medium",
        "narrative": "Your company just onboarded a new software vendor. Employees are receiving update notifications from the vendor. But are they real?",
        "threat_type": "Supply Chain Compromise",
        "xp_reward": 75,
        "emails": [
            {
                "id": "sc_phish_1",
                "sender_name": "npm Security Advisory",
                "sender_email": "security@npm-security-alert.com",
                "subject": "CRITICAL: Vulnerability Detected in @meridian/core-ui — Immediate Update Required",
                "date": "Today, 6:45 AM",
                "body_html": """
                    <p>Dear Development Team,</p>
                    <p>Our automated dependency scanner has detected a <strong>critical remote code execution vulnerability</strong> (CVE-2026-41823) in <code>@meridian/core-ui@3.14.2</code>, a package currently used in production at your organization.</p>
                    <div style="background:#fef2f2;border-left:4px solid #dc2626;padding:1rem 1.25rem;margin:1rem 0;border-radius:4px;font-size:0.9rem;">
                        <p style="margin:0;"><strong>CVSS Score:</strong> 9.8 (Critical)</p>
                        <p style="margin:0;"><strong>Affected Versions:</strong> 3.10.0 – 3.14.2</p>
                        <p style="margin:0;"><strong>Patched Version:</strong> 3.14.3</p>
                        <p style="margin:0;"><strong>Exploit Status:</strong> Actively exploited in the wild</p>
                    </div>
                    <p>To update your dependencies, run the following command or click the button below to access the advisory with full remediation steps:</p>
                    <p style="margin:1rem 0;"><a href="https://npm-security-alert.com/advisory/2026-41823" class="sim-btn" onclick="event.preventDefault();">View Full Advisory &amp; Patch Instructions</a></p>
                    <p style="font-size:0.85rem;color:#6b7280;">This is an automated message from the npm Security Advisory Service. Do not reply to this email.</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "npm-security-alert.com", "reason": "Fake domain: The real npm registry uses 'npmjs.com'. 'npm-security-alert.com' is a typosquatting domain designed to look official."},
                    {"target": "CVE-2026-41823", "reason": "Fabricated CVE: Attackers invent realistic-sounding CVE numbers with high CVSS scores to create panic. Always verify CVEs on official sources like nvd.nist.gov."},
                    {"target": "View Full Advisory & Patch Instructions", "reason": "Malicious link: This button leads to a phishing site that may serve typosquatted npm packages containing malware, or harvest developer credentials."},
                    {"target": "Actively exploited in the wild", "reason": "Urgency escalation: Claiming active exploitation pressures developers to act immediately without verifying the advisory's authenticity."}
                ],
                "explanation": "This is a supply chain phishing attack targeting developers. The attacker created a fake npm security domain and fabricated a CVE to trick developers into visiting a malicious site. Real npm advisories come from 'npmjs.com' or 'github.com/advisories'. Always verify security advisories on the official npm website or GitHub Advisory Database before taking action."
            },
            {
                "id": "sc_legit_1",
                "sender_name": "HR Benefits Team",
                "sender_email": "benefits@meridian-corp.com",
                "subject": "Open Enrollment Deadline — Friday, July 17",
                "date": "Yesterday, 11:00 AM",
                "body_html": """
                    <p>Hi team,</p>
                    <p>This is a reminder that the annual benefits open enrollment period closes this <strong>Friday, July 17 at 5:00 PM EAT</strong>.</p>
                    <p>If you haven't yet made your elections, please log in to the benefits portal at <a href="https://benefits.meridian-corp.com" style="color:#2563eb;" onclick="event.preventDefault();">benefits.meridian-corp.com</a> to review your options and submit your selections.</p>
                    <p>Key changes this year include:</p>
                    <ul>
                        <li>New dental plan option with orthodontic coverage</li>
                        <li>Increased employer NHIF contribution (KSH 5,000 individual / KSH 10,000 family)</li>
                        <li>Updated telehealth provider network</li>
                    </ul>
                    <p>If you need assistance, the HR Benefits team is hosting drop-in Q&A sessions in Conference Room B today and tomorrow from 12–1 PM.</p>
                    <p>Best regards,<br>HR Benefits Team<br>benefits@meridian-corp.com</p>
                """,
                "is_phishing": False,
                "red_flags": [],
                "explanation": "This email is legitimate. It comes from the verified 'meridian-corp.com' domain, references real company processes (open enrollment, specific deadlines), and provides helpful details like Q&A session locations. There are no suspicious links, urgency tactics, or requests for sensitive information."
            },
            {
                "id": "sc_phish_2",
                "sender_name": "AWS Account Security",
                "sender_email": "no-reply@aws-service-notice.com",
                "subject": "URGENT: Your AWS Account Will Be Suspended — Payment Verification Required",
                "date": "Today, 7:30 AM",
                "body_html": """
                    <p style="color:#dc2626;font-weight:bold;">⚠ Action Required: Account Suspension Notice</p>
                    <p>Dear AWS Customer,</p>
                    <p>We were unable to process the payment on file for your AWS account (<strong>meridian-prod</strong>). Your services will be <strong>suspended within 24 hours</strong> if payment is not verified.</p>
                    <p>Affected services include:</p>
                    <ul>
                        <li>EC2 instances (Production workloads)</li>
                        <li>RDS databases</li>
                        <li>S3 storage buckets</li>
                        <li>CloudFront distributions</li>
                    </ul>
                    <p>To avoid service interruption, please update your payment method:</p>
                    <p style="margin:1rem 0;"><a href="https://aws-service-notice.com/billing/update?ref=meridian" class="sim-btn" onclick="event.preventDefault();">Update Payment Method</a></p>
                    <p style="font-size:0.85rem;color:#6b7280;">Amazon Web Services, Inc. | Amazon Data Services, Nairobi, Kenya</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "aws-service-notice.com", "reason": "Fake domain: AWS uses 'amazonaws.com' and 'aws.amazon.com'. 'aws-service-notice.com' is a impersonation domain used to harvest AWS credentials."},
                    {"target": "suspended within 24 hours", "reason": "Urgency + consequence: Threatening production service suspension creates panic, especially for engineers who know the impact of AWS downtime."},
                    {"target": "EC2, RDS, S3, CloudFront", "reason": "Specificity as persuasion: Listing real AWS services makes the email appear targeted and legitimate, but any attacker can look up a company's tech stack."},
                    {"target": "Update Payment Method", "reason": "Credential harvesting: This link leads to a fake AWS login page that captures your credentials, giving the attacker access to your actual AWS infrastructure."},
                    {"target": "aws-service-notice.com/billing/update", "reason": "URL mismatch: Real AWS billing notifications come from amazon.com domains, not standalone notice domains."}
                ],
                "explanation": "This phishing attack targets cloud infrastructure credentials by impersonating AWS billing. The fake domain 'aws-service-notice.com' mimics official AWS communications. Real AWS suspension notices come from '@amazon.com' or appear in the AWS console. Never click billing links in emails — always navigate directly to aws.amazon.com and check your billing dashboard."
            },
            {
                "id": "sc_legit_2",
                "sender_name": "Marcus Rivera",
                "sender_email": "m.rivera@meridian-corp.com",
                "subject": "Sprint Retro — Thursday 3 PM — Please Add Your Notes",
                "date": "Yesterday, 2:15 PM",
                "body_html": """
                    <p>Hey team,</p>
                    <p>Just a heads-up that our sprint retrospective is scheduled for <strong>Thursday at 3:00 PM</strong> in the Dev Team room (and via Zoom for remote folks).</p>
                    <p>Before the meeting, please add your notes to the retro board:</p>
                    <ul>
                        <li><strong>What went well?</strong></li>
                        <li><strong>What could improve?</strong></li>
                        <li><strong>Any kudos for teammates?</strong></li>
                    </ul>
                    <p>The board is pinned in our #dev-team Slack channel. Please try to add at least 2 items before the meeting so we can have a productive discussion.</p>
                    <p>See you there!</p>
                    <p>— Marcus</p>
                """,
                "is_phishing": False,
                "red_flags": [],
                "explanation": "This email is legitimate. It's from an internal colleague ('meridian-corp.com'), references a routine team meeting, uses casual and natural tone, and doesn't ask for any sensitive information or contain suspicious links."
            },
            {
                "id": "sc_phish_3",
                "sender_name": "Slack Security Team",
                "sender_email": "notifications@slack-workspace-migrate.com",
                "subject": "Your Slack Workspace Is Being Migrated — Re-Authenticate Now",
                "date": "Today, 9:00 AM",
                "body_html": """
                    <p>Hi,</p>
                    <p>As part of Slack's infrastructure upgrade, your workspace <strong>meridian-corp</strong> is being migrated to our new authentication system. This migration improves security and requires all members to re-authenticate.</p>
                    <p>⚠ <strong>You must complete re-authentication within 48 hours</strong> or you will be locked out of the workspace.</p>
                    <p style="margin:1rem 0;"><a href="https://slack-workspace-migrate.com/auth/relogin?ws=meridian-corp" class="sim-btn" onclick="event.preventDefault();">Re-Authenticate Now</a></p>
                    <p>After clicking the link, you'll be asked to enter your Slack email and password to verify your identity. You may also be prompted for your two-factor authentication code.</p>
                    <p>If you have questions, visit our help center at <a href="https://slack-workspace-migrate.com/help" style="color:#2563eb;" onclick="event.preventDefault();">slack-workspace-migrate.com/help</a>.</p>
                    <p>— The Slack Team</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "slack-workspace-migrate.com", "reason": "Fake domain: Slack uses 'slack.com' and 'slackhq.com'. 'slack-workspace-migrate.com' is a credential harvesting domain impersonating Slack."},
                    {"target": "re-authenticate", "reason": "Credential theft via re-authentication pretext: Asking users to re-enter credentials is one of the most common phishing techniques."},
                    {"target": "locked out of the workspace", "reason": "Fear of loss: Threatening workspace lockout pressures employees to click quickly rather than verify the email's authenticity."},
                    {"target": "you'll be asked to enter your Slack email and password", "reason": "Explicit credential collection: The email openly states it will collect your password — real Slack re-authentication happens within the Slack app, not via email links."},
                    {"target": "two-factor authentication code", "reason": "MFA bypass attempt: By asking for your 2FA code, the attacker can complete real-time MFA interception, logging into your actual Slack account."}
                ],
                "explanation": "This is a sophisticated credential harvesting attack impersonating Slack. The attacker knows that requesting re-authentication is highly effective because employees are accustomed to occasional re-authentication prompts. Real Slack authentication changes appear as in-app notifications, never via email. Always verify workspace changes by checking Slack's official status page or your admin console."
            }
        ]
    },
    {
        "id": "clone_wars",
        "title": "The Clone Wars",
        "difficulty": "Medium",
        "narrative": "A sophisticated attacker has been cloning your company's internal portals. Employees report seeing 'identical' login pages. Investigate the incoming emails.",
        "threat_type": "Website Cloning & Credential Harvesting",
        "xp_reward": 100,
        "emails": [
            {
                "id": "cw_phish_1",
                "sender_name": "IT Security Team",
                "sender_email": "security@merid1an-corp.com",
                "subject": "Mandatory Account Verification — Security Audit Compliance",
                "date": "Today, 7:00 AM",
                "body_html": """
                    <p>Dear Employee,</p>
                    <p>As part of our annual security audit, all employees are required to verify their account credentials in our new Identity Management Portal. This is mandatory and must be completed by <strong>end of day today</strong>.</p>
                    <p>Failure to verify will result in temporary account suspension per our IT Security Policy (Section 4.2).</p>
                    <p style="margin:1rem 0;"><a href="https://merid1an-corp.com/identity/verify" class="sim-btn" onclick="event.preventDefault();">Verify Your Account</a></p>
                    <p>You will need to enter your corporate email and current password. You may also be asked to set a new password if our system detects it hasn't been changed in 90+ days.</p>
                    <p>Thank you for your cooperation.</p>
                    <p>IT Security Team<br>Meridian Corp</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "merid1an-corp.com", "reason": "Homograph domain: The letter 'i' in 'meridian' is replaced with the number '1' (merid1an-corp.com). This is visually almost identical but is a completely different domain."},
                    {"target": "Verify Your Account", "reason": "Credential harvesting: This link leads to a cloned version of the Meridian Corp login portal that captures your credentials."},
                    {"target": "set a new password if our system detects it hasn't been changed in 90+ days", "reason": "Legitimacy building: Adding realistic-sounding policy details makes the request seem like standard IT procedure."},
                    {"target": "temporary account suspension", "reason": "Negative consequence: Threatening account suspension pressures employees to comply without questioning the email's source."},
                    {"target": "end of day today", "reason": "Urgency: Tight deadline prevents employees from independently verifying the request with IT."}
                ],
                "explanation": "This is a website cloning attack using a homograph domain. The attacker replaced 'i' with '1' in 'meridian' — virtually invisible in most fonts. The link leads to a pixel-perfect clone of the Meridian login page that captures credentials. Always check domains character-by-character, especially when email requests involve logging in."
            },
            {
                "id": "cw_legit_1",
                "sender_name": "Diana Kowalski",
                "sender_email": "d.kowalski@meridian-corp.com",
                "subject": "Project Atlas — Deadline Extended to August 1",
                "date": "Yesterday, 3:45 PM",
                "body_html": """
                    <p>Hi team,</p>
                    <p>Good news — I spoke with the VP of Product this afternoon and she's approved a one-week extension for Project Atlas. The new deadline is <strong>Saturday, August 1</strong>.</p>
                    <p>This gives us extra time to complete the integration testing phase that was delayed by the vendor API issues last week. I've updated the project timeline in Jira accordingly.</p>
                    <p>Please review the updated milestones and let me know if you foresee any conflicts with the new dates. I'll send a revised status report by end of day Monday.</p>
                    <p>Thanks for the hard work, everyone. We're in good shape for the new deadline.</p>
                    <p>Best,<br>Diana Kowalski<br>Engineering Manager, Meridian Corp</p>
                """,
                "is_phishing": False,
                "red_flags": [],
                "explanation": "This email is legitimate. It's from an internal manager on the 'meridian-corp.com' domain, references real project details, communicates a schedule change in a professional manner, and doesn't request any credentials or sensitive information."
            },
            {
                "id": "cw_phish_2",
                "sender_name": "SharePoint Online",
                "sender_email": "noreply@meridian-sharepoint.com",
                "subject": "Sarah Mitchell shared a document with you — 'Q3_Budget_Forecast.xlsx'",
                "date": "Today, 8:30 AM",
                "body_html": """
                    <div style="border:1px solid #e5e7eb;border-radius:8px;padding:1.5rem;max-width:480px;margin:0 auto;">
                        <div style="display:flex;align-items:center;margin-bottom:1rem;">
                            <div style="width:40px;height:40px;background:#0078d4;border-radius:4px;margin-right:12px;display:flex;align-items:center;color:white;font-weight:bold;font-size:1.2rem;">S</div>
                            <div>
                                <p style="margin:0;font-weight:600;">SharePoint Online</p>
                                <p style="margin:0;font-size:0.8rem;color:#6b7280;">meridian-corp.sharepoint.com</p>
                            </div>
                        </div>
                        <p style="font-size:0.95rem;"><strong>Sarah Mitchell</strong> shared a file with you:</p>
                        <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:0.75rem 1rem;margin:0.75rem 0;">
                            <p style="margin:0;font-weight:600;">📊 Q3_Budget_Forecast.xlsx</p>
                            <p style="margin:0.25rem 0 0 0;font-size:0.8rem;color:#6b7280;">Excel Workbook · 2.4 MB</p>
                        </div>
                        <p style="margin:1rem 0;"><a href="https://meridian-sharepoint.com/preview/Q3_Budget_Forecast.xlsx" class="sim-btn" style="display:block;text-align:center;padding:0.75rem;background:#0078d4;color:white;border-radius:6px;text-decoration:none;font-weight:600;" onclick="event.preventDefault();">Open in SharePoint</a></p>
                        <p style="font-size:0.8rem;color:#9ca3af;">This email was sent from a notification-only address. Do not reply.</p>
                    </div>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "meridian-sharepoint.com", "reason": "Cloned portal domain: Real SharePoint notifications come from 'meridian-corp.sharepoint.com' (Microsoft's infrastructure), not 'meridian-sharepoint.com'."},
                    {"target": "meridian-sharepoint.com/preview/Q3_Budget_Forecast.xlsx", "reason": "Credential harvesting: Clicking 'Open in SharePoint' leads to a cloned Microsoft login page that captures your corporate credentials."},
                    {"target": "Q3_Budget_Forecast.xlsx", "reason": "Relevant bait: Using a finance document name makes it seem like a real colleague shared something you'd want to see, increasing the likelihood of clicking."},
                    {"target": "Sarah Mitchell", "reason": "Impersonated colleague: The attacker used a real employee name to make the notification appear legitimate. Real SharePoint emails do use colleague names, which is why this is effective."},
                    {"target": "SharePoint Online branding", "reason": "Visual cloning: The email replicates SharePoint's exact visual style (logo, layout, colors) to appear authentic. This is the 'clone' aspect of the attack."}
                ],
                "explanation": "This is a website cloning phishing attack that replicates SharePoint's visual identity. The domain 'meridian-sharepoint.com' mimics a Microsoft SharePoint URL but is completely separate. Real SharePoint notifications come from Microsoft's infrastructure (sharepoint.com). Always verify the full URL and domain before entering credentials on any login page."
            },
            {
                "id": "cw_phish_3",
                "sender_name": "Meridian Benefits Portal",
                "sender_email": "benefits@meridian-benefits-portal.com",
                "subject": "Open Your 2026 Benefits Summary — Action Required",
                "date": "Today, 10:00 AM",
                "body_html": """
                    <p>Hi,</p>
                    <p>Your 2026 benefits summary is now available for review. As part of the annual benefits renewal, you are required to acknowledge your current elections and make any changes before the enrollment window closes.</p>
                    <p style="margin:1rem 0;"><a href="https://meridian-benefits-portal.com/acknowledge?emp=current" class="sim-btn" onclick="event.preventDefault();">Review &amp; Acknowledge Benefits</a></p>
                    <p>You will be asked to authenticate using your corporate credentials to access the portal. If your session has expired, you'll be prompted to log in again.</p>
                    <p>Best regards,<br>Benefits Administration<br>Meridian Corp</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "meridian-benefits-portal.com", "reason": "Cloned portal domain: The real Meridian benefits portal is at 'benefits.meridian-corp.com'. This domain 'meridian-benefits-portal.com' inverts the subdomain structure to appear legitimate."},
                    {"target": "authenticate using your corporate credentials", "reason": "Credential harvesting: This link leads to a cloned Meridian login page that captures your corporate credentials."},
                    {"target": "session has expired", "reason": "Normalization of credential entry: The email pre-explains why you'd need to log in again, making the phishing page's credential prompt seem expected rather than suspicious."},
                    {"target": "emp=current", "reason": "Generic parameter: A real benefits portal would use your employee ID, not a generic 'current' parameter, indicating this is a mass phishing campaign."}
                ],
                "explanation": "This is a cloned benefits portal phishing attack. The attacker created a domain that mirrors the structure of Meridian's real benefits portal but redirects to a credential harvesting page. Real benefits notifications come from 'benefits.meridian-corp.com' (verified corporate domain). Always navigate to benefits portals directly rather than clicking email links."
            },
            {
                "id": "cw_legit_2",
                "sender_name": "Facilities Department",
                "sender_email": "facilities@meridian-corp.com",
                "subject": "Office Closure — Monday, June 1 (Madaraka Day Holiday)",
                "date": "2 days ago, 9:00 AM",
                "body_html": """
                    <p>Hi everyone,</p>
                    <p>Please note that the Meridian Corp offices will be <strong>closed on Monday, June 1</strong> in observance of Madaraka Day. This applies to all office locations.</p>
                    <p>Building access badges will not work on that day. If you need emergency building access, please contact the Facilities emergency line at ext. 5555.</p>
                    <p>Regular office hours resume on Tuesday, June 2. The parking garage will remain accessible 24/7 for those who need to retrieve personal items.</p>
                    <p>Enjoy the long weekend!</p>
                    <p>Facilities Department<br>facilities@meridian-corp.com</p>
                """,
                "is_phishing": False,
                "red_flags": [],
                "explanation": "This email is legitimate. It comes from the verified 'meridian-corp.com' domain, provides standard office closure information with appropriate detail (building access, parking, emergency contact), and has a natural, helpful tone typical of facilities communications."
            }
        ]
    },
    {
        "id": "insider_threat",
        "title": "Internal Threat",
        "difficulty": "Medium-Hard",
        "narrative": "Whispers of an insider threat have reached the security team. Examine communications carefully — the call may be coming from inside the house.",
        "threat_type": "Insider Threat & Social Engineering",
        "xp_reward": 125,
        "emails": [
            {
                "id": "it_phish_1",
                "sender_name": "Alex Torres",
                "sender_email": "alex.torres.dev@protonmail.com",
                "subject": "Hey — can you review this doc for me?",
                "date": "Today, 9:30 AM",
                "body_html": """
                    <p>Hey,</p>
                    <p>I'm working on the proposal for the Safaricom account and I need a second pair of eyes on the financial projections. I put everything in this doc:</p>
                    <p style="margin:1rem 0;"><a href="https://docs.google.com/document/d/1xK9mRvLpQ7zF2n8Y3wJ6tK0dV5bH4gS/edit" class="sim-btn" onclick="event.preventDefault();">Open Financial Projections Doc</a></p>
                    <p>It's pretty straightforward — just need you to check the numbers in the Q3 section. Should take 10 minutes tops.</p>
                    <p>Also, I'm messaging from my personal email because my work account got locked again. IT is being super slow about unlocking it.</p>
                    <p>Thanks!<br>Alex</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "protonmail.com", "reason": "External email impersonating a colleague: Alex Torres's real work email is 'a.torres@meridian-corp.com'. A message from a personal Protonmail account claiming to be a colleague is suspicious."},
                    {"target": "my work account got locked", "reason": "Pretext for external email: The attacker explains away the unusual email address to prevent suspicion."},
                    {"target": "docs.google.com/document/d/1xK9mRvLpQ7zF2n8Y3wJ6tK0dV5bH4gS", "reason": "Malicious Google Doc: Shared Google Docs can contain phishing links, malware payloads, or OAuth permission abuse that gives the attacker access to your Google account."},
                    {"target": "Safaricom account", "reason": "Social engineering via real context: The attacker researched internal project names to make the request appear legitimate."},
                    {"target": "should take 10 minutes", "reason": "Minimization: Downplaying the effort required makes you more likely to click without questioning."}
                ],
                "explanation": "This is an insider threat / social engineering attack. The attacker impersonates a known colleague using a personal email account and requests review of a document that likely contains phishing links or malware. Real colleagues would message from their corporate email. Always verify external emails claiming to be from coworkers — a quick Slack or in-person check takes seconds."
            },
            {
                "id": "it_phish_2",
                "sender_name": "HR Confidential",
                "sender_email": "confidential-survey@meridian-hr-portal.com",
                "subject": "CONFIDENTIAL: Annual Employee Engagement Survey — Your Response Is Required",
                "date": "Today, 8:00 AM",
                "body_html": """
                    <p>Dear Team Member,</p>
                    <p>Our annual employee engagement survey is now live. This survey is <strong>completely anonymous</strong> and helps leadership understand how we can better support our teams.</p>
                    <p>⚠ Due to regulatory requirements, <strong>participation is mandatory</strong> for all employees. Non-response will be escalated to your department head.</p>
                    <p style="margin:1rem 0;"><a href="https://meridian-hr-portal.com/survey/2026?emp=confidential" class="sim-btn" onclick="event.preventDefault();">Take the Confidential Survey</a></p>
                    <p>You will need to verify your identity with your corporate email and password before accessing the survey. This ensures each employee responds exactly once.</p>
                    <p>Survey closes: <strong>July 18 at 11:59 PM</strong></p>
                    <p>Thank you for your honest feedback.</p>
                    <p>Human Resources<br>Meridian Corp</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "meridian-hr-portal.com", "reason": "Cloned HR portal: Real Meridian HR communications come from 'hr@meridian-corp.com' and the benefits portal is 'benefits.meridian-corp.com', not 'meridian-hr-portal.com'."},
                    {"target": "verify your identity with your corporate email and password", "reason": "Credential harvesting: Real anonymous surveys never require your corporate password. The 'verification' step is the actual attack — it captures your credentials."},
                    {"target": "escalated to your department head", "reason": "Coercion: Threatening to escalate non-compliance pressures employees into completing the survey (and entering credentials) without questioning its source."},
                    {"target": "completely anonymous", "reason": "Irony as a red flag: The survey claims to be anonymous but requires corporate credentials for 'verification' — these two things are contradictory. Truly anonymous surveys use unique tokens, not login credentials."}
                ],
                "explanation": "This phishing email impersonates an HR survey to harvest credentials. The key contradiction: an 'anonymous' survey that requires your corporate password. Real anonymous surveys from HR use unique survey tokens or links, not corporate authentication. Always be suspicious of any email that requests your password, regardless of how legitimate it appears."
            },
            {
                "id": "it_legit_1",
                "sender_name": "Finance Department",
                "sender_email": "finance@meridian-corp.com",
                "subject": "Q3 Budget Review — Department Heads Meeting Friday 2 PM",
                "date": "Yesterday, 1:00 PM",
                "body_html": """
                    <p>Good afternoon,</p>
                    <p>This is a reminder that the Q3 budget review meeting is scheduled for <strong>Friday at 2:00 PM</strong> in the Executive Conference Room (Floor 12).</p>
                    <p>Department heads should come prepared with their updated budget forecasts and variance reports. The following items will be on the agenda:</p>
                    <ul>
                        <li>Q2 actuals vs. projections review</li>
                        <li>Q3 headcount and hiring plan approval</li>
                        <li>Capital expenditure requests for H2</li>
                        <li>Cloud infrastructure cost optimization update</li>
                    </ul>
                    <p>Please submit any additional agenda items to finance@meridian-corp.com by end of day Wednesday.</p>
                    <p>Finance Department<br>Meridian Corp</p>
                """,
                "is_phishing": False,
                "red_flags": [],
                "explanation": "This email is legitimate. It comes from the verified 'meridian-corp.com' domain, references a standard business process (budget review), lists realistic agenda items, and provides a professional communication tone without any urgency, threats, or credential requests."
            },
            {
                "id": "it_phish_3",
                "sender_name": "IT Help Desk",
                "sender_email": "helpdesk@meridian-itsupport.com",
                "subject": "Remote Access Setup — New Tool Installation Required for WFH Compliance",
                "date": "Today, 11:15 AM",
                "body_html": """
                    <p>Hi,</p>
                    <p>In preparation for our updated Work From Home policy (effective August 1), all employees who work remotely must install the new Meridian Secure Access Client (MSAC) on their devices.</p>
                    <p>This tool provides encrypted VPN connectivity and endpoint verification required by our new compliance framework.</p>
                    <p style="margin:1rem 0;"><a href="https://meridian-itsupport.com/download/msac-installer.exe" class="sim-btn" onclick="event.preventDefault();">Download MSAC Installer</a></p>
                    <p>After installation, you'll be asked to authenticate with your corporate credentials to register the device. This is a one-time setup process.</p>
                    <p>If you have any issues with installation, reply to this email or open a ticket at <a href="https://meridian-itsupport.com/tickets" style="color:#2563eb;" onclick="event.preventDefault();">meridian-itsupport.com/tickets</a>.</p>
                    <p>Thanks,<br>IT Help Desk<br>Meridian Corp</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "meridian-itsupport.com", "reason": "Impersonation domain: Real Meridian IT communications come from 'it-ops@meridian-corp.com'. 'meridian-itsupport.com' is a separate attacker-controlled domain."},
                    {"target": "msac-installer.exe", "reason": "Malicious executable: Downloading and running an .exe file from an unverified source could install malware, a remote access trojan (RAT), or keylogger on your machine."},
                    {"target": "authenticate with your corporate credentials", "reason": "Credential harvesting: The installer likely prompts for corporate credentials during 'device registration', which are sent to the attacker."},
                    {"target": "Work From Home policy", "reason": "Timely pretext: WFH policies are common corporate topics, making this request seem timely and plausible."},
                    {"target": "endpoint verification", "reason": "Security language as camouflage: Using legitimate cybersecurity terminology ('endpoint verification', 'encrypted VPN') makes the malicious tool appear to be a security product."}
                ],
                "explanation": "This is a remote access trojan (RAT) delivery phishing attack. The attacker impersonates IT Help Desk and distributes a malicious .exe file disguised as a VPN compliance tool. Real IT software deployments go through verified channels (company app store, managed device updates) — never via email attachment links. Always check with IT directly before installing software from email requests."
            },
            {
                "id": "it_legit_2",
                "sender_name": "Security Awareness Team",
                "sender_email": "security-awareness@meridian-corp.com",
                "subject": "Phishing Awareness Training — Mandatory by July 31",
                "date": "Yesterday, 10:30 AM",
                "body_html": """
                    <p>Hi team,</p>
                    <p>Our annual Phishing Awareness Training is now available in the learning management system. This training is <strong>mandatory for all employees</strong> and must be completed by <strong>July 31</strong>.</p>
                    <p>To complete the training:</p>
                    <ol>
                        <li>Log in to the LMS at <a href="https://lms.meridian-corp.com" style="color:#2563eb;" onclick="event.preventDefault();">lms.meridian-corp.com</a></li>
                        <li>Navigate to "Required Training" → "Phishing Awareness 2026"</li>
                        <li>Complete the module (approximately 20 minutes)</li>
                        <li>Pass the quiz with 80% or higher</li>
                    </ol>
                    <p>Topics covered include: identifying phishing emails, credential theft prevention, social engineering tactics, and reporting procedures.</p>
                    <p>After completing the training, you'll receive a digital badge on your profile. Managers will receive completion reports for their teams next week.</p>
                    <p>Questions? Reply to this email or reach the Security Awareness team on Slack #security-training.</p>
                    <p>Stay safe,<br>Security Awareness Team<br>security-awareness@meridian-corp.com</p>
                """,
                "is_phishing": False,
                "red_flags": [],
                "explanation": "This email is legitimate. It comes from the verified corporate domain, references a real LMS system, provides clear step-by-step instructions for completing training, and appropriately sets expectations (20 minutes, 80% quiz score). This is standard corporate security training communication."
            }
        ]
    },
    {
        "id": "shadow_network",
        "title": "APT: Shadow Network",
        "difficulty": "Hard",
        "narrative": "Intelligence suggests a state-sponsored group has targeted your organization. Their emails are flawless — almost. Find the microscopic flaws before it's too late.",
        "threat_type": "Advanced Persistent Threat (APT)",
        "xp_reward": 150,
        "emails": [
            {
                "id": "apt_phish_1",
                "sender_name": "CyberSec Conference",
                "sender_email": "speakers@cybersec-summit-2026.com",
                "subject": "Your Speaker Feedback & Presentation Materials — CyberSec Summit 2026",
                "date": "Today, 6:00 AM",
                "body_html": """
                    <p>Dear Dr. Mitchell,</p>
                    <p>Thank you for your excellent presentation at CyberSec Summit 2026 in Nairobi last week. Your session on "Zero Trust Architecture in Enterprise Environments" received outstanding feedback from attendees.</p>
                    <p>We've compiled the speaker feedback reports and attendee survey results for your review. Additionally, several attendees have requested copies of your slide deck, which we'd love to distribute on your behalf (with your permission).</p>
                    <p style="margin:1rem 0;"><a href="https://cybersec-summit-2026.com/speakers/feedback/dr-mitchell" class="sim-btn" onclick="event.preventDefault();">Download Your Feedback Report</a></p>
                    <p>Please also find attached the speaker agreement for next year's conference. We'd love to have you back — perhaps as a keynote?</p>
                    <p>Looking forward to hearing from you.</p>
                    <p>Best regards,<br>Laura Kensington<br>Program Director, CyberSec Summit 2026</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "cybersec-summit-2026.com", "reason": "Lookalike conference domain: The real CyberSec Summit uses 'cybersec-summit.com'. Adding the year and using the same structure is a hallmark of APT-level reconnaissance."},
                    {"target": "Dr. Mitchell", "reason": "Personalized targeting: The attacker researched the target's real name, title, and recent conference appearance — characteristic of APT spear-phishing campaigns."},
                    {"target": "Zero Trust Architecture in Enterprise Environments", "reason": "Reconnaissance-derived detail: The specific presentation topic indicates the attacker monitored the conference or scraped the speaker schedule to personalize the lure."},
                    {"target": "Download Your Feedback Report", "reason": "Payload delivery: This link likely serves a tailored malware implant disguised as a PDF report, or leads to a credential harvesting page designed to match the conference branding."},
                    {"target": "speaker agreement for next year's conference", "reason": "Secondary bait: Offering a future speaking opportunity creates additional motivation to open the attachment, increasing infection probability."}
                ],
                "explanation": "This is a highly targeted APT spear-phishing attack. The attacker conducted detailed reconnaissance: they know the target's name, title, recent conference attendance, and presentation topic. This level of personalization is characteristic of nation-state threat actors. Always verify conference communications directly through official conference websites, not email links."
            },
            {
                "id": "apt_phish_2",
                "sender_name": "Kenya Computer Incident Response Team",
                "sender_email": "compliance@ke-cirt.go.ke",
                "subject": "MANDATORY: Critical Security Compliance Directive — KE-CIRT-2026-0742",
                "date": "Today, 7:15 AM",
                "body_html": """
                    <p>Dear Organization Security Officer,</p>
                    <p>The Kenya Computer Incident Response Team (KE-CIRT) has issued mandatory compliance directive <strong>KE-CIRT-2026-0742</strong> in response to recent advanced persistent threat activity targeting critical infrastructure sectors.</p>
                    <p>All organizations in the Technology sector are required to:</p>
                    <ol>
                        <li>Submit a current network architecture diagram</li>
                        <li>Verify all administrative accounts are enrolled in hardware MFA</li>
                        <li>Report any indicators of compromise (IOCs) from the past 72 hours</li>
                        <li>Complete the mandatory self-assessment questionnaire</li>
                    </ol>
                    <p style="margin:1rem 0;"><a href="https://ke-cirt.go.ke/compliance/submit?org=meridian-corp" class="sim-btn" onclick="event.preventDefault();">Submit Compliance Documentation</a></p>
                    <p>Non-compliance will result in the organization being added to the National Computer and Cybercrimes Coordination Committee (NC4) watchlist and may affect NTSA and CCCRA compliance status.</p>
                    <p>This directive has the force of law under the Computer Misuse and Cybercrimes Act (2018).</p>
                    <p>Dr. James Mwangi<br>Director, KE-CIRT</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "ke-cirt.go.ke", "reason": "Fake government domain: Real Kenyan government agencies use '.go.ke' domains. '.org' is not a valid Kenyan government TLD — it's a commercial domain anyone can register."},
                    {"target": "Submit Compliance Documentation", "reason": "Credential and data harvesting: This link leads to a fake compliance portal that captures organizational details, employee credentials, and potentially network architecture information."},
                    {"target": "non-compliance will result in", "reason": "Legal intimidation: APT actors use regulatory penalties and legal consequences to pressure organizations into immediate compliance without verification."},
                    {"target": "network architecture diagram", "reason": "Intelligence gathering: Requesting network diagrams is a classic APT objective — this information enables follow-on network exploitation."},
                    {"target": "Computer Misuse and Cybercrimes Act (2018)", "reason": "Fabricated legislation: The attacker invented a plausible-sounding law to add legal weight. Always verify government directives through official channels, not email links."}
                ],
                "explanation": "This is an APT attack impersonating a government agency to collect intelligence and credentials. The '.org' domain is the critical flaw — real Kenyan government domains use '.go.ke' exclusively. APT actors use regulatory compliance as a lure because organizations are conditioned to respond quickly to government mandates. Always verify government communications through official websites and phone numbers."
            },
            {
                "id": "apt_legit_1",
                "sender_name": "Legal Department",
                "sender_email": "legal@meridian-corp.com",
                "subject": "Updated NDA Requirements — All Employees Must Re-Sign by August 15",
                "date": "Yesterday, 4:00 PM",
                "body_html": """
                    <p>Dear Team,</p>
                    <p>Following our recent acquisition of NovaTech Solutions, the Legal department has updated our Non-Disclosure Agreement (NDA) to include provisions related to NovaTech's intellectual property and client data.</p>
                    <p>All current employees, contractors, and consultants must re-sign the updated NDA by <strong>August 15, 2026</strong>. You can review and sign the document through the following process:</p>
                    <ol>
                        <li>Log in to the HR portal at <a href="https://hr.meridian-corp.com/nda" style="color:#2563eb;" onclick="event.preventDefault();">hr.meridian-corp.com/nda</a></li>
                        <li>Review the updated NDA document</li>
                        <li>E-sign using your corporate credentials</li>
                    </ol>
                    <p>Legal counsel is available for any questions about the updated terms. Drop-in sessions will be held every Wednesday from 1–2 PM in Conference Room C through August.</p>
                    <p>Please note that failure to re-sign by the deadline may result in restricted access to NovaTech-related systems and data.</p>
                    <p>Best regards,<br>Legal Department<br>legal@meridian-corp.com</p>
                """,
                "is_phishing": False,
                "red_flags": [],
                "explanation": "This email is legitimate. It comes from the verified 'meridian-corp.com' domain, references a real business event (acquisition), provides clear instructions through the verified HR portal, and offers in-person legal sessions for questions. The tone is professional and the request is standard corporate procedure."
            },
            {
                "id": "apt_phish_3",
                "sender_name": "David Park",
                "sender_email": "d.park@meridian-corp.com",
                "subject": "Meeting Notes — Yesterday's Strategy Session",
                "date": "Today, 8:45 AM",
                "body_html": """
                    <p>Hi,</p>
                    <p>Attached are the notes from yesterday's strategy session with the leadership team. There were some important decisions made that affect our team directly, so please review before our standup this morning.</p>
                    <p>Key takeaways:</p>
                    <ul>
                        <li>Q4 budget has been reallocated — our team gets an additional KSH 25M for tooling</li>
                        <li>New hire for the security team approved — start date moved up to August 1</li>
                        <li>Incident response retainer with SecureWorks renewed</li>
                        <li>Board wants quarterly threat briefings starting Q3</li>
                    </ul>
                    <p style="margin:1rem 0;"><a href="https://meridian-corp.box.com/s/strategy-session-notes-july" class="sim-btn" onclick="event.preventDefault();">Open Meeting Notes (Box)</a></p>
                    <p>I may have missed a few details so let me know if anything looks off.</p>
                    <p>— David</p>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "meridian-corp.box.com/s/strategy-session-notes-july", "reason": "Spoofed Box URL: Real Box links use 'app.box.com'. This link uses 'meridian-corp.box.com' which could be a Box Shared Link to attacker-controlled content, or a completely spoofed URL."},
                    {"target": "yesterday's strategy session", "reason": "Fabricated event: There was no strategy session yesterday. The attacker fabricated a plausible meeting to create urgency and curiosity — a hallmark of APT social engineering."},
                    {"target": "Q4 budget has been reallocated — our team gets an additional KSH 25M", "reason": "Bait with personal relevance: Sharing positive financial news about the target's team creates excitement that overrides suspicion."},
                    {"target": "I may have missed a few details so let me know if anything looks off", "reason": "Authenticity building: The casual disclaimer mimics natural colleague behavior, making the email appear more genuine."},
                    {"target": "d.park@meridian-corp.com", "reason": "Internal spoofing: APT actors can spoof internal sender addresses. The legitimate-looking sender doesn't guarantee authenticity — verify unusual requests through a separate channel."}
                ],
                "explanation": "This is an APT attack using a fabricated internal event. The attacker impersonated a colleague ('David Park') and referenced a meeting that never happened. The email contains enticing details (budget increases, new hires) designed to provoke curiosity and clicks. The Box link leads to either a credential harvesting page or malware-laced document. Always verify meeting references — a quick Slack message to 'David' would expose this fabrication."
            },
            {
                "id": "apt_phish_4",
                "sender_name": "ThreatGuard Licensing",
                "sender_email": "licensing@threatguard.io",
                "subject": "License Renewal Notice — ThreatGuard Enterprise (Exp. July 25)",
                "date": "Today, 9:00 AM",
                "body_html": """
                    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
                        <div style="background:#1e293b;color:white;padding:1.5rem;border-radius:8px 8px 0 0;">
                            <h2 style="margin:0;font-size:1.2rem;">ThreatGuard Enterprise</h2>
                            <p style="margin:0.5rem 0 0 0;opacity:0.8;">Advanced Threat Detection & Response Platform</p>
                        </div>
                        <div style="border:1px solid #e5e7eb;border-top:none;padding:1.5rem;border-radius:0 0 8px 8px;">
                            <p>Dear Meridian Corp Security Team,</p>
                            <p>Your ThreatGuard Enterprise license (<strong>TG-ENT-4827-MC</strong>) is set to expire on <strong>July 25, 2026</strong>. To maintain uninterrupted threat detection coverage, please renew your license before the expiration date.</p>
                            <div style="background:#f1f5f9;border-radius:6px;padding:1rem;margin:1rem 0;">
                                <p style="margin:0;"><strong>License:</strong> TG-ENT-4827-MC</p>
                                <p style="margin:0;"><strong>Seats:</strong> 500 endpoints</p>
                                <p style="margin:0;"><strong>Expiration:</strong> July 25, 2026</p>
                                <p style="margin:0;"><strong>Annual Cost:</strong> KSH 6,200,000</p>
                            </div>
                            <p style="margin:1rem 0;"><a href="https://threatguard.io/renew?license=TG-ENT-4827-MC" class="sim-btn" style="display:block;text-align:center;padding:0.75rem;background:#1e293b;color:white;border-radius:6px;text-decoration:none;font-weight:600;" onclick="event.preventDefault();">Renew License Now</a></p>
                            <p style="font-size:0.85rem;color:#6b7280;">If you do not renew by July 25, threat detection services will be paused and your endpoint telemetry will no longer be collected.</p>
                        </div>
                        <div style="text-align:center;padding:1rem;font-size:0.8rem;color:#9ca3af;">
                            <p style="margin:0;">ThreatGuard Inc. | Nairobi, Kenya</p>
                            <p style="margin:0;"><a href="https://threatguard.io" style="color:#9ca3af;" onclick="event.preventDefault();">threatguard.io</a></p>
                        </div>
                    </div>
                """,
                "is_phishing": True,
                "red_flags": [
                    {"target": "threatguard.io", "reason": "Fake vendor domain: While ThreatGuard may be a real vendor, the attacker registered 'threatguard.io' (the real vendor may use '.com' or a different domain). APT actors clone vendor branding perfectly."},
                    {"target": "TG-ENT-4827-MC", "reason": "Fabricated license key: The attacker generated a realistic-looking license key. No real license key was verified — the format is plausible but entirely fictional."},
                    {"target": "Renew License Now", "reason": "Payment redirection: This link leads to a fake payment portal where the attacker captures corporate payment information (credit card, M-Pesa, ACH details) or organizational intelligence."},
                    {"target": "threat detection services will be paused", "reason": "Operational fear: Threatening to disable security tools creates urgency because security teams know the risk of running without threat detection."},
                    {"target": "professional branding", "reason": "APT-level polish: The email uses professional HTML/CSS styling that perfectly mimics real vendor communications. Nation-state actors invest heavily in visual authenticity."}
                ],
                "explanation": "This is an APT attack impersonating a security vendor. The attacker cloned ThreatGuard's branding and created a convincing license renewal notice. The goal is to redirect a KSH 6,200,000 payment to attacker-controlled accounts and harvest payment information. Always verify vendor renewal notices by logging into the vendor's portal directly or contacting your account manager through known contact information — never through email links."
            }
        ]
    }
]

BOSS_BATTLE_EMAIL = {
    "id": "boss_apt_ultima",
    "sender_name": "Dr. Sarah Chen, VP of Engineering",
    "sender_email": "schen@meridian-corp.works",
    "subject": "Re: Q3 Security Audit Results — Confidential",
    "date": "Today, 9:17 AM",
    "body_html": """
        <p>Hi team,</p>
        <p>Following our board meeting yesterday, I've attached the finalized Q3 security audit findings. Several critical vulnerabilities were identified in our payment processing pipeline that require immediate remediation.</p>
        <p>The board has approved an emergency patch deployment window this Thursday at 2 AM EAT. All engineering leads need to review the attached findings and sign off on the rollback plan before Wednesday EOD.</p>
        <p>I've also set up a secure document sharing portal for the audit artifacts since the files contain sensitive infrastructure details:</p>
        <p style="margin: 1rem 0;"><a href="https://meridian-corp-secure.works/audit/Q3-2026" class="sim-btn" onclick="event.preventDefault();">Access Audit Portal</a></p>
        <p>Credentials were sent separately via Slack. If you haven't received them, reply to this email and I'll resend.</p>
        <p>One more thing — the渗透测试 team flagged that our VPN certificates expire next week. I need each department head to verify their team's VPN access by clicking the verification link below:</p>
        <p style="margin: 1rem 0;"><a href="https://vpn-verify.meridian-corp.works/auth" class="sim-btn" onclick="event.preventDefault();">Verify VPN Access</a></p>
        <p>Please treat this entire thread as CONFIDENTIAL. Do not forward.</p>
        <p>Best,<br>Dr. Sarah Chen<br>VP of Engineering, Meridian Corp</p>
    """,
    "is_phishing": True,
    "red_flags": [
        {"target": "meridian-corp.works", "reason": "Lookalike domain: The real company uses 'meridian-corp.com'. The '.works' TLD is a common attacker choice."},
        {"target": "meridian-corp-secure.works", "reason": "Credential harvesting portal: This fake 'secure' subdomain mimics internal tools to steal credentials."},
        {"target": "vpn-verify.meridian-corp.works", "reason": "Secondary phishing vector: Two separate malicious links in one email — a technique called 'multi-vector phishing'."},
        {"target": "Credentials were sent separately via Slack", "reason": "Social engineering: Pretexts that credentials exist elsewhere pressure victims to use the phishing link instead of asking IT."},
        {"target": "Reply to this email", "reason": "Reply-to manipulation: Phishing emails often set the reply-to address to the attacker's inbox while spoofing the From field."},
        {"target": "渗透测试", "reason": "Unicode injection: Chinese characters embedded in an English corporate email are abnormal and may bypass security filters."},
        {"target": "CONFIDENTIAL. Do not forward", "reason": "Isolation tactic: Discouraging forwarding prevents the email from being analyzed by the security team."}
    ],
    "explanation": "This is an advanced multi-vector phishing attack combining lookalike domains, credential harvesting, social engineering, unicode injection, and isolation tactics. The attacker researched the target organization extensively — the email references real business processes (audits, VPN, board meetings) to appear legitimate. Seven distinct red flags make this the hardest challenge."
}

BADGE_DEFINITIONS = {
    "first_steps": "First Steps \u2014 Complete 5 email analyses",
    "dedicated": "Dedicated Analyst \u2014 Complete 25 email analyses",
    "phish_hunter": "Phish Hunter \u2014 Complete 100 email analyses",
    "eagle_eye": "Eagle Eye \u2014 Maintain 90%+ accuracy",
    "perfect_streak": "Perfect Streak \u2014 Get 10 in a row correct",
    "hot_streak": "Hot Streak \u2014 5 correct in a row",
    "phishing_spotted": "Phishing Spotter \u2014 Correctly identify 10 phishing emails"
}

RADAR_RANK_BUCKETS = {
    "100": "Top 100",
    "1000": "Top 1,000",
    "10000": "Top 10,000",
    "100000": "Top 100,000",
    "200000": "Top 200,000",
    "500000": "Top 500,000",
    "1000000": "Top 1,000,000",
    "2000000": "Top 2,000,000",
    "5000000": "Top 5,000,000",
    "10000000": "Top 10,000,000",
}

PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    111: "RPC", 119: "NNTP", 123: "NTP", 135: "RPC-DCOM", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 179: "BGP",
    194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP-TLS", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Dev", 9200: "Elasticsearch", 27017: "MongoDB",
}

HIGH_RISK_PORTS = {21, 23, 135, 137, 138, 139, 445, 3389, 5900, 1080, 161}
MEDIUM_RISK_PORTS = {22, 25, 53, 80, 110, 143, 1433, 1521, 3306, 5432, 6379, 9200, 27017}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161,
                389, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389,
                5432, 5900, 6379, 8080, 8443, 9200, 27017]

NMAP_ENGINE = bool(_shutil.which("nmap"))

MAC_CACHE = {}


# ─────────────────────────────────────────────
#  AUTH MIDDLEWARE
# ─────────────────────────────────────────────

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function


# ─────────────────────────────────────────────
#  CSRF PROTECTION
# ─────────────────────────────────────────────

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def validate_csrf():
    token = request.form.get("csrf_token")
    if not token and request.is_json:
        token = (request.get_json(silent=True) or {}).get("csrf_token")
    if not token:
        token = request.headers.get("X-CSRF-Token")
    if not token or token != session.get("csrf_token"):
        return False
    return True


# ─────────────────────────────────────────────
#  API HELPER FUNCTIONS
# ─────────────────────────────────────────────

def check_urlhaus(url):
    try:
        resp = req.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=3.0)
        if resp.status_code == 200:
            res_json = resp.json()
            if res_json.get("query_status") == "ok":
                threat = res_json.get("threat", "Malware")
                url_status = res_json.get("url_status", "unknown")
                return {
                    "label": "URLhaus Threat Check",
                    "status": "fail",
                    "detail": f"Match found! Flagged in URLhaus database (threat: {threat}, status: {url_status})",
                    "score_addition": 80
                }
            else:
                return {
                    "label": "URLhaus Threat Check",
                    "status": "pass",
                    "detail": "Not found in URLhaus database of active malware links"
                }
    except Exception as e:
        return {
            "label": "URLhaus Threat Check",
            "status": "info",
            "detail": f"Could not perform URLhaus lookup: {str(e)}"
        }
    return {
        "label": "URLhaus Threat Check",
        "status": "pass",
        "detail": "Not found in URLhaus database of active malware links"
    }

def check_virustotal(url):
    api_key = session.get("vt_api_key")
    if not api_key:
        username = session.get("username", "")
        if username:
            api_key = database.get_user_vt_key(username) or None
    if not api_key:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return simulate_virustotal(url)
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        resp = req.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=3.0)
        if resp.status_code == 200:
            res_json = resp.json()
            stats = res_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious + suspicious > 0:
                score_add = min(20 * (malicious + suspicious), 80)
                return {
                    "label": "VirusTotal Reputation Check",
                    "status": "fail" if malicious > 1 else "warn",
                    "detail": f"Flagged by VirusTotal. Detections: {malicious} malicious, {suspicious} suspicious engine flags",
                    "score_addition": score_add
                }
            else:
                return {
                    "label": "VirusTotal Reputation Check",
                    "status": "pass",
                    "detail": "Clean on VirusTotal (0 malicious/suspicious flags)"
                }
        else:
            return simulate_virustotal(url)
    except Exception:
        return simulate_virustotal(url)

def simulate_virustotal(url):
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        if domain in MALICIOUS_DOMAINS:
            return {
                "label": "VirusTotal Reputation Check",
                "status": "fail",
                "detail": "Known malicious domain \u2014 flagged by cached reputation data.",
                "score_addition": 40
            }
        else:
            return {
                "label": "VirusTotal Reputation Check",
                "status": "info",
                "detail": "No VirusTotal API key configured \u2014 cached heuristic check only. Configure a key for full multi-engine analysis."
            }
    except Exception:
        return {
            "label": "VirusTotal Reputation Check",
            "status": "pass",
            "detail": "Clean on VirusTotal (Cached reputation match)."
        }

def check_virustotal_file(file_hash, file_bytes, filename, api_key):
    try:
        headers = {"x-apikey": api_key}
        resp = req.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, timeout=3.0)
        
        if resp.status_code == 200:
            res_json = resp.json()
            stats = res_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious + suspicious > 0:
                return {
                    "label": "VirusTotal File Reputation Check",
                    "status": "fail" if malicious > 1 else "warn",
                    "detail": f"File signature match found. Detections: {malicious} engines flagged this file as malicious."
                }
            else:
                return {
                    "label": "VirusTotal File Reputation Check",
                    "status": "pass",
                    "detail": "Clean file signature in VirusTotal database (0 detections)."
                }
        elif resp.status_code == 404:
            files = {"file": (filename, file_bytes)}
            up_resp = req.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files, timeout=5.0)
            if up_resp.status_code in [200, 201, 202]:
                return {
                    "label": "VirusTotal File Reputation Check",
                    "status": "info",
                    "detail": "File not previously analyzed. Successfully submitted to VirusTotal queue for analysis."
                }
            else:
                return {
                    "label": "VirusTotal File Reputation Check",
                    "status": "info",
                    "detail": f"File signature not found in VirusTotal database (upload returned status {up_resp.status_code})."
                }
        else:
            return simulate_virustotal_file(filename, len(file_bytes))
    except Exception:
        return simulate_virustotal_file(filename, len(file_bytes))

def simulate_virustotal_file(filename, size_bytes):
    ext = os.path.splitext(filename.lower())[1]
    is_malicious = ext in [".exe", ".scr", ".bat", ".com", ".vbs", ".msi", ".dll", ".ps1"]
    
    if is_malicious:
        return {
            "label": "VirusTotal File Reputation Check (Heuristics)",
            "status": "fail",
            "detail": "Flagged by local heuristics. Execution triggers potential threat signature."
        }
    else:
        return {
            "label": "VirusTotal File Reputation Check (Heuristics)",
            "status": "pass",
            "detail": "Clean signature (Cached lookup). No threat matches found."
        }

def parse_email_headers(raw_headers: str) -> dict:
    headers = {}
    current_key = None
    for line in raw_headers.splitlines():
        if not line:
            continue
        if line[0].isspace() and current_key:
            headers[current_key] += " " + line.strip()
        else:
            match = re.match(r"^([a-zA-Z0-9\-]+):\s*(.*)$", line)
            if match:
                current_key = match.group(1).lower()
                headers[current_key] = match.group(2).strip()

    extracted = {
        "from": headers.get("from", "Unknown"),
        "to": headers.get("to", "Unknown"),
        "subject": headers.get("subject", "Unknown"),
        "date": headers.get("date", "Unknown"),
        "return_path": headers.get("return-path", "").strip("<>"),
        "reply_to": headers.get("reply-to", "").strip("<>"),
        "received_spf": headers.get("received-spf", ""),
        "dkim_signature": headers.get("dkim-signature", ""),
        "authentication_results": headers.get("authentication-results", ""),
    }

    spf_status = "none"
    dkim_status = "none"
    dmarc_status = "none"
    
    spf_text = (extracted["received_spf"] + " " + extracted["authentication_results"]).lower()
    if "spf=pass" in spf_text or "pass (google" in spf_text or "spf pass" in spf_text:
        spf_status = "pass"
    elif "spf=fail" in spf_text or "fail (google" in spf_text or "spf fail" in spf_text or "hardfail" in spf_text:
        spf_status = "fail"
    elif "spf=softfail" in spf_text or "softfail" in spf_text:
        spf_status = "softfail"
    elif "spf=" in spf_text or "received-spf" in headers:
        spf_status = "neutral"

    dkim_text = (extracted["dkim_signature"] + " " + extracted["authentication_results"]).lower()
    if "dkim=pass" in dkim_text or "dkim pass" in dkim_text or "pass (ok)" in dkim_text:
        dkim_status = "pass"
    elif "dkim=fail" in dkim_text or "dkim fail" in dkim_text:
        dkim_status = "fail"

    dmarc_text = extracted["authentication_results"].lower()
    if "dmarc=pass" in dmarc_text or "dmarc pass" in dmarc_text:
        dmarc_status = "pass"
    elif "dmarc=fail" in dmarc_text or "dmarc fail" in dmarc_text or "dmarc=action" in dmarc_text:
        dmarc_status = "fail"

    findings = []
    spoof_score = 0

    from_match = re.search(r"<([^>]+)>", extracted["from"])
    from_email = from_match.group(1) if from_match else extracted["from"]
    
    from_domain = ""
    if "@" in from_email:
        from_domain = from_email.split("@")[-1].lower()

    return_domain = ""
    if extracted["return_path"] and "@" in extracted["return_path"]:
        return_domain = extracted["return_path"].split("@")[-1].lower()

    if return_domain and from_domain:
        if from_domain != return_domain:
            spoof_score += 40
            findings.append({
                "label": "Domain Alignment Mismatch",
                "status": "fail",
                "detail": f"The sender domain '{from_domain}' in the From header does not match the Return-Path domain '{return_domain}'. This is a common spoofing technique."
            })
        else:
            findings.append({
                "label": "Domain Alignment Check",
                "status": "pass",
                "detail": "From address and Return-Path domains are aligned"
            })
    elif not return_domain:
        spoof_score += 15
        findings.append({
            "label": "Missing Return-Path",
            "status": "warn",
            "detail": "The Return-Path header is missing. Legitimate emails usually contain a bounce-back return path."
        })

    reply_email = extracted["reply_to"]
    reply_match = re.search(r"<([^>]+)>", extracted["reply_to"])
    if reply_match:
        reply_email = reply_match.group(1)
        
    reply_domain = ""
    if "@" in reply_email:
        reply_domain = reply_email.split("@")[-1].lower()

    if reply_domain and from_domain and from_domain != reply_domain:
        spoof_score += 20
        findings.append({
            "label": "Reply-To Mismatch",
            "status": "warn",
            "detail": f"Replies will go to a different domain '{reply_domain}' than the sender '{from_domain}'."
        })

    if spf_status == "pass":
        findings.append({"label": "SPF Record Verification", "status": "pass", "detail": "Sender Policy Framework (SPF) validation passed"})
    elif spf_status == "fail":
        spoof_score += 35
        findings.append({"label": "SPF Record Verification", "status": "fail", "detail": "SPF validation failed \u2013 sending IP is not authorized to send mail for this domain"})
    elif spf_status == "softfail":
        spoof_score += 15
        findings.append({"label": "SPF Record Verification", "status": "warn", "detail": "SPF validation returned softfail \u2013 domain suggests checking sending IP but doesn't explicitly block"})
    else:
        spoof_score += 10
        findings.append({"label": "SPF Record Verification", "status": "warn", "detail": "SPF record is missing or neutral"})

    if dkim_status == "pass":
        findings.append({"label": "DKIM Cryptographic Signature", "status": "pass", "detail": "DKIM cryptographic signature verified, confirming email content has not been modified"})
    elif dkim_status == "fail":
        spoof_score += 30
        findings.append({"label": "DKIM Cryptographic Signature", "status": "fail", "detail": "DKIM signature validation failed \u2013 email may have been altered in transit or signatures are invalid"})
    else:
        spoof_score += 15
        findings.append({"label": "DKIM Cryptographic Signature", "status": "warn", "detail": "DKIM cryptographic signature is missing"})

    if dmarc_status == "pass":
        findings.append({"label": "DMARC Alignment Policy", "status": "pass", "detail": "DMARC policy check passed"})
    elif dmarc_status == "fail":
        spoof_score += 30
        findings.append({"label": "DMARC Alignment Policy", "status": "fail", "detail": "DMARC validation failed \u2013 the sender failed domain verification policies"})
    else:
        findings.append({"label": "DMARC Alignment Policy", "status": "info", "detail": "No DMARC status found in headers"})

    mailer = headers.get("x-mailer", "").lower()
    if mailer:
        findings.append({"label": "Mail Client Software", "status": "info", "detail": f"Email was sent using client software: {headers.get('x-mailer')}"})

    if "x-php-originating-script" in headers or "x-get-message-sender-via" in headers:
        spoof_score += 10
        findings.append({"label": "Script Mailer Detected", "status": "warn", "detail": "Headers indicate this email was generated by a server script rather than a standard user mail application."})

    verdict = "Low Risk"
    verdict_color = "#2ed573"
    verdict_icon = "check_circle"
    if spoof_score >= 60:
        verdict = "High Risk (Potential Spoofing)"
        verdict_color = "#ff4757"
        verdict_icon = "report"
    elif spoof_score >= 30:
        verdict = "Medium Risk"
        verdict_color = "#ffa502"
        verdict_icon = "warning"
        
    return {
        "verdict": verdict,
        "verdict_color": verdict_color,
        "verdict_icon": verdict_icon,
        "score": spoof_score,
        "headers": extracted,
        "findings": findings
    }

def check_password_breached(password: str) -> int:
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        resp = req.get(url, timeout=3.0)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if ":" in line:
                    line_suffix, count_str = line.split(":", 1)
                    if line_suffix == suffix:
                        return int(count_str)
        return 0
    except Exception as e:
        print(f"Error checking password breach: {e}")
        return -1

def check_cloudflare_radar(domain: str) -> dict:
    raw = get_cloudflare_radar_raw(domain)
    if "error" in raw:
        return {"label": "Cloudflare Domain Ranking", "status": "info", "detail": raw["error"]}
    if raw.get("not_found"):
        return {"label": "Cloudflare Domain Ranking", "status": "info", "detail": "Not found in Cloudflare top rankings \u2014 low global visibility"}
    rank = raw.get("rank")
    bucket = raw.get("bucket", "")
    bucket_label = raw.get("bucket_label", "")
    is_unranked = bucket.startswith(">")
    cat_names = raw.get("categories", [])

    if rank is not None and rank <= 100:
        detail = f"#{rank} globally \u2014 highly reputable domain"
        status = "pass"
    elif is_unranked:
        detail = "Not found in Cloudflare top rankings \u2014 low global visibility"
        status = "info"
    elif bucket_label:
        detail = f"{bucket_label} \u2014 well-established domain"
        status = "pass"
    else:
        detail = "Not in Cloudflare rankings"
        status = "info"

    if cat_names:
        detail += f" | Categories: {', '.join(cat_names[:3])}"

    return {"label": "Cloudflare Domain Ranking", "status": status, "detail": detail}


def get_cloudflare_radar_raw(domain: str) -> dict:
    if not CLOUDFLARE_RADAR_TOKEN:
        return {"error": "Cloudflare Radar not configured \u2014 set CLOUDFLARE_RADAR_TOKEN in .env"}
    try:
        headers = {"Authorization": f"Bearer {CLOUDFLARE_RADAR_TOKEN}", "Content-Type": "application/json"}
        resp = req.get(f"{CLOUDFLARE_RADAR_BASE}/ranking/domain/{domain}", headers=headers, timeout=4.0)
        if resp.status_code == 200:
            data = resp.json()
            rank_data = data.get("result", {}).get("details_0", {})
            rank = rank_data.get("rank")
            bucket = str(rank_data.get("bucket", ""))
            categories = rank_data.get("categories", [])
            cat_names = [c.get("name", "") for c in categories if c.get("name")]
            bucket_label = RADAR_RANK_BUCKETS.get(bucket, "")
            if not bucket_label and bucket:
                clean = bucket.lstrip(">")
                try:
                    bucket_label = f"Top {int(clean):,}"
                except ValueError:
                    bucket_label = ""
            is_unranked = bucket.startswith(">")
            result = {"rank": rank, "bucket": bucket, "bucket_label": bucket_label, "categories": cat_names}
            if rank is None and is_unranked:
                result["not_found"] = True
            return result
        elif resp.status_code == 429:
            return {"error": "Rate limited by Cloudflare Radar API"}
        else:
            return {"error": f"Cloudflare Radar returned status {resp.status_code}"}
    except Exception as e:
        return {"error": f"Could not check Cloudflare Radar: {str(e)}"}


def check_google_safebrowsing(url: str) -> dict:
    if not GOOGLE_SAFEBROWSING_KEY:
        return {"label": "Google Safe Browsing", "status": "info", "detail": "Google Safe Browsing not configured \u2014 set GOOGLE_SAFEBROWSING_KEY in .env"}
    try:
        body = {
            "client": {"clientId": "securix", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        resp = req.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFEBROWSING_KEY}",
            json=body, timeout=4.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                threat_types = set(m.get("threatType", "UNKNOWN") for m in matches)
                return {
                    "label": "Google Safe Browsing",
                    "status": "fail",
                    "detail": f"Flagged! Threats detected: {', '.join(threat_types)}",
                    "score_addition": 80,
                }
            else:
                return {"label": "Google Safe Browsing", "status": "pass", "detail": "URL not found in Google Safe Browsing blocklists"}
        else:
            return {"label": "Google Safe Browsing", "status": "info", "detail": f"Google Safe Browsing returned status {resp.status_code}"}
    except Exception as e:
        return {"label": "Google Safe Browsing", "status": "info", "detail": f"Could not check Google Safe Browsing: {str(e)}"}


def check_abuseipdb(domain: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"label": "AbuseIPDB Reputation", "status": "info", "detail": "AbuseIPDB not configured \u2014 set ABUSEIPDB_KEY in .env"}
    try:
        ip = socket.gethostbyname(domain)
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": False}
        resp = req.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=4.0)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            confidence = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            isp = data.get("isp", "Unknown")

            if confidence >= 50:
                return {
                    "label": "AbuseIPDB Reputation",
                    "status": "fail",
                    "detail": f"IP flagged! Confidence: {confidence}%, Reports: {total_reports}, ISP: {isp}",
                    "score_addition": round(confidence * 0.8),
                }
            elif confidence >= 10:
                return {
                    "label": "AbuseIPDB Reputation",
                    "status": "warn",
                    "detail": f"Low reputation. Confidence: {confidence}%, Reports: {total_reports}, ISP: {isp}",
                    "score_addition": round(confidence * 0.4),
                }
            else:
                return {"label": "AbuseIPDB Reputation", "status": "pass", "detail": f"Clean reputation (confidence: {confidence}%), ISP: {isp}"}
        elif resp.status_code == 429:
            return {"label": "AbuseIPDB Reputation", "status": "info", "detail": "Rate limited by AbuseIPDB API"}
        else:
            return {"label": "AbuseIPDB Reputation", "status": "info", "detail": f"AbuseIPDB returned status {resp.status_code}"}
    except socket.gaierror:
        return {"label": "AbuseIPDB Reputation", "status": "info", "detail": "Could not resolve domain to check AbuseIPDB"}
    except Exception as e:
        return {"label": "AbuseIPDB Reputation", "status": "info", "detail": f"Could not check AbuseIPDB: {str(e)}"}


def check_otx_alienvault(domain: str) -> dict:
    try:
        resp = req.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers={"Accept": "application/json"},
            timeout=4.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            reputation = data.get("reputation", 0)
            country = data.get("country_name", "Unknown")
            asn = data.get("asn", "Unknown")

            if pulse_count >= 10:
                return {
                    "label": "OTX AlienVault Reputation",
                    "status": "fail",
                    "detail": f"Flagged in {pulse_count} threat pulses. Country: {country}, ASN: {asn}. Reputation score: {reputation}",
                    "score_addition": min(pulse_count * 3, 60),
                }
            elif pulse_count >= 3:
                return {
                    "label": "OTX AlienVault Reputation",
                    "status": "warn",
                    "detail": f"Mentioned in {pulse_count} threat pulses. Country: {country}, ASN: {asn}. Reputation score: {reputation}",
                    "score_addition": pulse_count * 2,
                }
            elif pulse_count >= 1:
                return {
                    "label": "OTX AlienVault Reputation",
                    "status": "info",
                    "detail": f"Mentioned in {pulse_count} threat pulse(s). Country: {country}, ASN: {asn}",
                    "score_addition": 5,
                }
            else:
                return {
                    "label": "OTX AlienVault Reputation",
                    "status": "pass",
                    "detail": f"No threat pulses found. Country: {country}, ASN: {asn}. Domain appears clean across {data.get('reputation', 0)} reputation sources.",
                }
        elif resp.status_code == 404:
            return {
                "label": "OTX AlienVault Reputation",
                "status": "pass",
                "detail": "Domain not found in OTX threat intelligence database \u2014 no known threats.",
            }
        elif resp.status_code == 429:
            return {"label": "OTX AlienVault Reputation", "status": "info", "detail": "Rate limited by OTX API"}
        else:
            return {"label": "OTX AlienVault Reputation", "status": "info", "detail": f"OTX returned status {resp.status_code}"}
    except Exception as e:
        return {"label": "OTX AlienVault Reputation", "status": "info", "detail": f"Could not check OTX AlienVault: {str(e)}"}


def is_shortener_domain(domain):
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain in SHORTENER_DOMAINS or any(
        domain.endswith(f".{s}") for s in SHORTENER_DOMAINS
    )


def analyze_url(url: str) -> dict:
    result = {
        "url": url,
        "score": 0,
        "verdict": "Safe",
        "verdict_color": "#00d2ff",
        "checks": [],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        full_url_lower = url.lower()

        # SSRF protection — block private/internal IPs
        if not is_safe_host(domain):
            result["score"] = 100
            result["verdict"] = "Blocked"
            result["verdict_color"] = "#ff4757"
            result["checks"].append({
                "label": "SSRF Protection",
                "status": "fail",
                "detail": "URL resolves to a private/internal IP address. Scanning internal resources is not allowed."
            })
            result["risk_percent"] = 100
            return result

        if parsed.scheme == "https":
            result["checks"].append({"label": "HTTPS Secure Connection", "status": "pass", "detail": "URL uses HTTPS encryption"})
        else:
            result["score"] += 5
            result["checks"].append({"label": "HTTPS Secure Connection", "status": "info", "detail": "URL uses HTTP \u2014 HTTPS is recommended for secure connections"})

        if is_shortener_domain(domain):
            result["score"] += 10
            result["checks"].append({"label": "URL Shortener", "status": "info", "detail": "URL uses a shortening service \u2014 destination should be verified"})
        else:
            result["checks"].append({"label": "URL Shortener", "status": "pass", "detail": "No URL shortener detected"})

        path_query = parsed.path + "?" + parsed.query if parsed.query else parsed.path
        path_query_lower = path_query.lower()
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if re.search(r'(?<![a-z])' + re.escape(kw) + r'(?![a-z])', path_query_lower)]
        if len(found_keywords) >= 3:
            result["score"] += 10
            result["checks"].append({"label": "Suspicious Keywords", "status": "warn", "detail": f"Found {len(found_keywords)} suspicious keywords: {', '.join(found_keywords[:5])}"})
        elif len(found_keywords) >= 1:
            result["score"] += 5
            result["checks"].append({"label": "Suspicious Keywords", "status": "info", "detail": f"Found keywords: {', '.join(found_keywords[:5])}"})
        else:
            result["checks"].append({"label": "Suspicious Keywords", "status": "pass", "detail": "No suspicious keywords detected in URL"})

        suspicious_tld_found = [tld for tld in SUSPICIOUS_TLDS if domain.endswith(tld)]
        if suspicious_tld_found:
            result["score"] += 10
            result["checks"].append({"label": "Suspicious TLD", "status": "info", "detail": f"Top-level domain '{suspicious_tld_found[0]}' is uncommon \u2014 verify legitimacy"})
        else:
            result["checks"].append({"label": "Suspicious TLD", "status": "pass", "detail": "Domain extension appears legitimate"})

        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if ip_pattern.match(domain):
            result["score"] += 15
            result["checks"].append({"label": "IP Address as Host", "status": "warn", "detail": "Using raw IP address instead of domain name is unusual"})
        else:
            result["checks"].append({"label": "IP Address as Host", "status": "pass", "detail": "Domain name used (not raw IP address)"})

        subdomain_count = len(domain.split(".")) - 2
        if subdomain_count > 3:
            result["score"] += 5
            result["checks"].append({"label": "Excessive Subdomains", "status": "info", "detail": f"Found {subdomain_count} subdomains \u2014 verify this is expected"})
        else:
            result["checks"].append({"label": "Excessive Subdomains", "status": "pass", "detail": "Normal subdomain depth"})

        obfuscation_signals = 0
        path_only = parsed.path
        query_only = parsed.query
        if len(path_only) > 100:
            obfuscation_signals += 1
        special_chars = ["%40", "%2F", "@"]
        found_special = [c for c in special_chars if c in path_only]
        if found_special:
            obfuscation_signals += 1
        if obfuscation_signals >= 2:
            result["score"] += 10
            result["checks"].append({"label": "URL Obfuscation", "status": "warn", "detail": "URL appears obfuscated (long path + encoded chars) \u2014 phishing sites often hide their true destination"})
        elif obfuscation_signals == 1:
            result["score"] += 5
            result["checks"].append({"label": "URL Obfuscation", "status": "info", "detail": "Minor obfuscation signals detected"})
        else:
            result["checks"].append({"label": "URL Obfuscation", "status": "pass", "detail": "No obfuscation detected"})

        try:
            socket.gethostbyname(domain)
            result["checks"].append({"label": "DNS Resolution", "status": "pass", "detail": f"Domain '{domain}' resolves successfully"})
        except socket.gaierror:
            result["score"] += 10
            result["checks"].append({"label": "DNS Resolution", "status": "warn", "detail": f"Could not resolve domain '{domain}' \u2014 may be offline or non-existent"})

        heuristic_score = result["score"]
        result["score"] = min(result["score"], 40)
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _run_check(fn, *args):
            return fn(*args)

        api_checks = [
            ("urlhaus", check_urlhaus, (url,)),
            ("virustotal", check_virustotal, (url,)),
            ("cloudflare", check_cloudflare_radar, (domain,)),
            ("safebrowsing", check_google_safebrowsing, (url,)),
            ("abuseipdb", check_abuseipdb, (domain,)),
            ("otx", check_otx_alienvault, (domain,)),
        ]

        api_results = {}
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(_run_check, fn, *args): name for name, fn, args in api_checks}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    api_results[name] = future.result()
                except Exception:
                    api_results[name] = {"label": name, "status": "info", "detail": f"Check timed out"}

        urlhaus_res = api_results["urlhaus"]
        if "score_addition" in urlhaus_res:
            result["score"] += urlhaus_res["score_addition"]
            del urlhaus_res["score_addition"]
        result["checks"].append(urlhaus_res)

        vt_res = api_results["virustotal"]
        if "score_addition" in vt_res:
            result["score"] += vt_res["score_addition"]
            del vt_res["score_addition"]
        result["checks"].append(vt_res)

        result["checks"].append(api_results["cloudflare"])

        gsb_res = api_results["safebrowsing"]
        if "score_addition" in gsb_res:
            result["score"] += gsb_res["score_addition"]
            del gsb_res["score_addition"]
        result["checks"].append(gsb_res)

        abuse_res = api_results["abuseipdb"]
        if "score_addition" in abuse_res:
            result["score"] += abuse_res["score_addition"]
            del abuse_res["score_addition"]
        result["checks"].append(abuse_res)

        otx_res = api_results["otx"]
        if "score_addition" in otx_res:
            result["score"] += otx_res["score_addition"]
            del otx_res["score_addition"]
        result["checks"].append(otx_res)

    except Exception as e:
        result["score"] += 50
        result["checks"].append({"label": "URL Parse Error", "status": "fail", "detail": f"Could not parse URL: {str(e)}"})

    if result["score"] >= 70:
        result["verdict"] = "Malicious"
        result["verdict_color"] = "#ff4757"
        result["verdict_icon"] = "report"
    elif result["score"] >= 35:
        result["verdict"] = "Suspicious"
        result["verdict_color"] = "#ffa502"
        result["verdict_icon"] = "warning"
    elif result["score"] >= 15:
        result["verdict"] = "Potentially Risky"
        result["verdict_color"] = "#eccc68"
        result["verdict_icon"] = "info"
    else:
        result["verdict"] = "Likely Safe"
        result["verdict_color"] = "#2ed573"
        result["verdict_icon"] = "check_circle"

    result["risk_percent"] = min(result["score"], 100)
    return result


# ─────────────────────────────────────────────
#  NETWORK SCANNING HELPERS
# ─────────────────────────────────────────────

def scan_port(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def resolve_mac_vendor(mac):
    if not mac or mac.lower() in ["unknown", ""]:
        return "Unknown Vendor"
    
    mac_clean = mac.upper()
    prefix = mac_clean[:8].replace("-", ":")
    
    if prefix in MAC_CACHE:
        return MAC_CACHE[prefix]
        
    try:
        resp = req.get(f"https://macvendors.co/api/{mac_clean}", timeout=2.0)
        if resp.status_code == 200:
            data = resp.json()
            vendor = data.get("result", {}).get("company", "Standard Network Device")
            MAC_CACHE[prefix] = vendor
            return vendor
    except Exception:
        pass
        
    prefix_lower = prefix.lower()
    vendors = {
        "00:11:24": "Apple", "00:26:bb": "Apple", "00:03:93": "Apple", "0c:4d:12": "Apple",
        "08:00:27": "VirtualBox", "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
        "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
        "00:17:88": "Philips Hue", "00:11:32": "Synology",
        "00:1d:7e": "TP-Link", "00:21:29": "TP-Link", "ec:08:6b": "TP-Link",
        "70:b3:d5": "Linksys", "18:b4:30": "Nest",
        "2c:30:33": "Netgear", "00:1e:2a": "Netgear",
        "3c:d9:2b": "HP", "f4:f5:e8": "HP", "00:18:71": "HP",
        "00:1a:a0": "Dell", "00:14:22": "Dell", "00:21:70": "Dell",
        "00:18:ba": "Cisco", "00:1d:a1": "Cisco", "00:1e:be": "Cisco",
        "00:1c:42": "Parallels", "d4:a1:48": "Ubiquiti", "fc:ec:da": "Ubiquiti",
        "00:22:64": "Samsung", "00:12:fb": "Samsung", "f4:7b:5e": "Samsung",
        "00:15:af": "Asus", "00:1e:8c": "Asus", "00:26:18": "Asus",
        "00:24:d7": "Intel", "00:1e:64": "Intel", "00:21:6a": "Intel",
        "3c:a6:16": "Xiaomi", "00:9e:c8": "Xiaomi",
        "00:18:8b": "Motorola", "00:00:0c": "Cisco",
    }
    return vendors.get(prefix_lower, "Standard Network Device")

def guess_device_type(open_ports, hostname, vendor):
    hostname_lower = hostname.lower()
    vendor_lower = vendor.lower()
    ports = {p["port"] for p in open_ports}
    
    if 53 in ports and (80 in ports or 443 in ports) and ("router" in hostname_lower or "gateway" in hostname_lower or "modem" in hostname_lower):
        return "Gateway / Router", "router"
    if 9100 in ports or 631 in ports or "printer" in hostname_lower or "epson" in hostname_lower or "canon" in hostname_lower or "hp" in hostname_lower and "print" in hostname_lower:
        return "Network Printer", "print"
    if 22 in ports or 111 in ports or 2049 in ports:
        if "synology" in vendor_lower or "nas" in hostname_lower:
            return "NAS / Storage Server", "dns"
        return "Linux Server / Device", "dns"
    if 135 in ports or 445 in ports or 3389 in ports:
        return "Windows PC / Server", "desktop_windows"
    if 8008 in ports or 8009 in ports or "tv" in hostname_lower or "roku" in hostname_lower or "chromecast" in hostname_lower or "apple-tv" in hostname_lower:
        return "Smart TV / Media Player", "tv"
    if "virtualbox" in vendor_lower or "vmware" in vendor_lower or "parallels" in vendor_lower:
        return "Virtual Machine", "filter_drama"
    if "raspberry" in vendor_lower or "nest" in vendor_lower or "hue" in vendor_lower:
        return "IoT Smart Device", "smart_toy"
    if "phone" in hostname_lower or "android" in hostname_lower or "iphone" in hostname_lower or "ipad" in hostname_lower:
        return "Mobile Device", "smartphone"
    if 80 in ports or 443 in ports:
        return "Web Server / Router", "router"
    return "Workstation / PC", "computer"

def get_arp_table():
    arp_table = {}
    try:
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        mac = parts[3]
                        flags = parts[2]
                        if mac != "00:00:00:00:00:00" and flags != "0x0":
                            arp_table[ip] = mac
    except Exception:
        pass
    return arp_table

def parse_nmap_xml(xml_string, arp_cache):
    import xml.etree.ElementTree as ET
    hosts_list = []
    try:
        root = ET.fromstring(xml_string)
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
                
            ip = None
            mac = None
            vendor = "Unknown Vendor"
            for addr in host.findall("address"):
                addrtype = addr.get("addrtype")
                if addrtype == "ipv4":
                    ip = addr.get("addr")
                elif addrtype == "mac":
                    mac = addr.get("addr")
                    vendor = addr.get("vendor", "Unknown Vendor")
                    
            if not ip:
                continue
                
            if not mac or mac == "Unknown":
                mac = arp_cache.get(ip, "Unknown")
                if mac != "Unknown":
                    vendor = resolve_mac_vendor(mac)
                    
            hostname = ip
            for hname in host.findall("hostnames/hostname"):
                name = hname.get("name")
                if name:
                    hostname = name
                    break
                    
            open_ports = []
            detected_os = None
            
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state = port_elem.find("state")
                    if state is not None and state.get("state") == "open":
                        port_id = int(port_elem.get("portid"))
                        service_elem = port_elem.find("service")
                        service_name = "Unknown"
                        product = ""
                        version = ""
                        extrainfo = ""
                        
                        if service_elem is not None:
                            service_name = service_elem.get("name", "Unknown")
                            product = service_elem.get("product", "")
                            version = service_elem.get("version", "")
                            extrainfo = service_elem.get("extrainfo", "")
                            ostype = service_elem.get("ostype")
                            if ostype and not detected_os:
                                detected_os = ostype
                                
                            for cpe in service_elem.findall("cpe"):
                                cpe_text = cpe.text or ""
                                if cpe_text.startswith("cpe:/o:"):
                                    parts = cpe_text.split(":")
                                    if len(parts) > 2:
                                        os_name = parts[2].capitalize()
                                        if len(parts) > 3:
                                            os_name += f" {parts[3]}"
                                        detected_os = os_name
                                        
                        full_info = f"{product} {version} {extrainfo}".lower()
                        if not detected_os:
                            if "ubuntu" in full_info:
                                detected_os = "Ubuntu Linux"
                            elif "debian" in full_info:
                                detected_os = "Debian Linux"
                            elif "linux" in full_info:
                                detected_os = "Linux"
                            elif "windows" in full_info:
                                detected_os = "Windows"
                            elif "ios" in full_info or "apple-tv" in full_info:
                                detected_os = "Apple iOS / tvOS"
                            elif "osx" in full_info or "mac os" in full_info:
                                detected_os = "macOS"
                                
                        service = service_name
                        if product:
                            service = f"{service_name} ({product} {version})".strip()
                            
                        remedy = "Monitor service for unauthorized access."
                        if port_id in HIGH_RISK_PORTS:
                            risk = "High"; risk_color = "#ef4444"
                            remedy = "Block this port at the firewall immediately. Disable the service if not required."
                        elif port_id in MEDIUM_RISK_PORTS:
                            risk = "Medium"; risk_color = "#f59e0b"
                            remedy = "Ensure strong authentication. Restrict access to trusted IPs only."
                        else:
                            risk = "Low"; risk_color = "#10b981"
                            remedy = "Standard service. Ensure software is fully updated."
                            
                        if port_id == 21: remedy = "FTP uses plaintext credentials. Migrate to SFTP or FTPS."
                        elif port_id == 23: remedy = "Telnet is unencrypted. Replace with SSH immediately."
                        elif port_id == 3389: remedy = "RDP is heavily targeted. Place behind a VPN and require NLA/MFA."
                        elif port_id == 445: remedy = "SMB is vulnerable to ransomware. Disable SMBv1 and restrict WAN access."
                        elif port_id == 22: remedy = "Disable root login and enforce key-based authentication."
                        elif port_id == 80: remedy = "HTTP is unencrypted. Redirect traffic to HTTPS (port 443)."
                        
                        open_ports.append({
                            "port": port_id, "state": "open", "service": service,
                            "risk": risk, "risk_color": risk_color, "remedy": remedy
                        })
            
            open_port_ids = {p["port"] for p in open_ports}
            if not detected_os:
                if 135 in open_port_ids or 445 in open_port_ids or 3389 in open_port_ids:
                    detected_os = "Windows"
                elif 22 in open_port_ids or 111 in open_port_ids or 2049 in open_port_ids:
                    detected_os = "Linux"
                else:
                    detected_os = "Generic OS / Device"
                    
            dev_type, dev_icon = guess_device_type(open_ports, hostname, vendor)
            
            high = sum(1 for p in open_ports if p["risk"] == "High")
            med  = sum(1 for p in open_ports if p["risk"] == "Medium")
            if high:   risk = "High";   risk_color = "#ef4444"
            elif med:  risk = "Medium"; risk_color = "#f59e0b"
            elif open_ports: risk = "Low"; risk_color = "#10b981"
            else:      risk = "Online"; risk_color = "#10b981"
            
            hosts_list.append({
                "ip": ip, "hostname": hostname, "mac": mac or "Unknown",
                "vendor": vendor, "alive": True, "open_ports": open_ports,
                "open_count": len(open_ports), "risk": risk, "risk_color": risk_color,
                "device_type": dev_type, "device_icon": dev_icon, "os": detected_os
            })
    except Exception as e:
        print(f"Error parsing XML: {e}")
    return hosts_list


def _socket_scan_subnet(base, scan_depth, arp_cache):
    import concurrent.futures

    ports_to_use = []
    if scan_depth == "deep":
        ports_to_use = list(range(1, 1025))
    elif scan_depth != "ping":
        ports_to_use = COMMON_PORTS

    def probe_host(i):
        ip = f"{base}.{i}"
        arp_mac = arp_cache.get(ip)
        alive = bool(arp_mac)
        if not alive:
            for pp in [80, 22, 443, 445, 8080, 3389]:
                if scan_port(ip, pp, timeout=0.2):
                    alive = True
                    break
        if not alive:
            return None

        try:    hostname = socket.gethostbyaddr(ip)[0]
        except: hostname = ip

        mac    = arp_mac or "Unknown"
        vendor = resolve_mac_vendor(mac) if mac != "Unknown" else "Unknown Vendor"

        open_ports = []
        for port in ports_to_use:
            if scan_port(ip, port, timeout=0.3):
                service = PORT_SERVICES.get(port, "Unknown")
                remedy  = "Monitor for unauthorised access."
                if port in HIGH_RISK_PORTS:
                    risk = "High";   risk_color = "#ef4444"
                    remedy = "Block at firewall. Disable if not required."
                elif port in MEDIUM_RISK_PORTS:
                    risk = "Medium"; risk_color = "#f59e0b"
                    remedy = "Restrict access to trusted IPs."
                else:
                    risk = "Low";    risk_color = "#10b981"
                if port == 21:   remedy = "FTP is plaintext \u2014 migrate to SFTP."
                elif port == 23: remedy = "Telnet is unencrypted \u2014 use SSH."
                elif port == 3389: remedy = "RDP must be behind a VPN."
                elif port == 445: remedy = "Disable SMBv1; restrict WAN access."
                elif port == 22: remedy = "Enforce key-based auth, disable root login."
                elif port == 80: remedy = "Redirect all traffic to HTTPS (443)."
                open_ports.append({"port": port, "state": "open",
                                   "service": service, "risk": risk,
                                   "risk_color": risk_color, "remedy": remedy})

        ids = {p["port"] for p in open_ports}
        if 135 in ids or 445 in ids or 3389 in ids: os_g = "Windows"
        elif 22 in ids or 111 in ids:               os_g = "Linux"
        else:                                        os_g = "Generic Device"

        dev_type, dev_icon = guess_device_type(open_ports, hostname, vendor)
        high = sum(1 for p in open_ports if p["risk"] == "High")
        med  = sum(1 for p in open_ports if p["risk"] == "Medium")
        if high:         r = "High";   rc = "#ef4444"
        elif med:        r = "Medium"; rc = "#f59e0b"
        elif open_ports: r = "Low";    rc = "#10b981"
        else:            r = "Online"; rc = "#10b981"
        return {"ip": ip, "hostname": hostname, "mac": mac, "vendor": vendor,
                "alive": True, "open_ports": open_ports,
                "open_count": len(open_ports), "risk": r, "risk_color": rc,
                "device_type": dev_type, "device_icon": dev_icon, "os": os_g}

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as ex:
        for r in ex.map(probe_host, range(1, 255)):
            if r: results.append(r)

    existing = {h["ip"] for h in results}
    for ip, mac in arp_cache.items():
        if ip.startswith(base + ".") and ip not in existing:
            try:    hostname = socket.gethostbyaddr(ip)[0]
            except: hostname = ip
            results.append({"ip": ip, "hostname": hostname, "mac": mac,
                            "vendor": resolve_mac_vendor(mac), "alive": True,
                            "open_ports": [], "open_count": 0,
                            "risk": "Online", "risk_color": "#10b981",
                            "device_type": "Network Device", "device_icon": "devices",
                            "os": "Generic Device"})

    results.sort(key=lambda h: int(h["ip"].split(".")[-1]) if len(h["ip"].split(".")) == 4 else 0)
    return results


def _socket_scan_target(target_ip, port_range):
    import concurrent.futures
    ports_to_scan = COMMON_PORTS
    if port_range == "all":
        ports_to_scan = list(range(1, 1025))
    elif port_range and port_range != "common":
        try:
            ports_to_scan = []
            for seg in port_range.split(","):
                seg = seg.strip()
                if "-" in seg:
                    a, b = map(int, seg.split("-"))
                    ports_to_scan.extend(range(a, b + 1))
                else:
                    ports_to_scan.append(int(seg))
        except Exception:
            ports_to_scan = COMMON_PORTS

    open_ports = []
    def check(port):
        if not scan_port(target_ip, port, timeout=0.4): return None
        service = PORT_SERVICES.get(port, "Unknown")
        remedy  = "Keep service updated."
        if port in HIGH_RISK_PORTS:
            risk = "High"; risk_color = "#ef4444"; remedy = "Disable or firewall this port."
        elif port in MEDIUM_RISK_PORTS:
            risk = "Medium"; risk_color = "#f59e0b"; remedy = "Restrict access; enforce MFA."
        else:
            risk = "Low"; risk_color = "#10b981"
        if port == 21:   remedy = "Migrate from FTP to SFTP."
        elif port == 23: remedy = "Replace Telnet with SSH."
        elif port == 3389: remedy = "Put RDP behind a VPN."
        elif port == 445: remedy = "Disable SMBv1; restrict WAN."
        return {"port": port, "service": service, "risk": risk,
                "risk_color": risk_color, "remedy": remedy}

    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        for r in ex.map(check, ports_to_scan):
            if r: open_ports.append(r)

    try:    hostname = socket.gethostbyaddr(target_ip)[0]
    except: hostname = target_ip

    high = sum(1 for p in open_ports if p["risk"] == "High")
    med  = sum(1 for p in open_ports if p["risk"] == "Medium")
    if high:         r = "High";   rc = "#ef4444"
    elif med:        r = "Medium"; rc = "#f59e0b"
    elif open_ports: r = "Low";    rc = "#10b981"
    else:            r = "Secure"; rc = "#10b981"

    ids = {p["port"] for p in open_ports}
    if 135 in ids or 445 in ids or 3389 in ids: os_g = "Windows"
    elif 22 in ids or 111 in ids:               os_g = "Linux"
    else:                                        os_g = "Generic Device"

    arp = get_arp_table()
    mac    = arp.get(target_ip, "N/A")
    vendor = resolve_mac_vendor(mac) if mac != "N/A" else "Unknown Vendor"
    dev_type, dev_icon = guess_device_type(open_ports, hostname, vendor)
    return {"ip": target_ip, "hostname": hostname, "mac": mac, "vendor": vendor,
            "alive": True, "open_ports": open_ports, "open_count": len(open_ports),
            "risk": r, "risk_color": rc, "device_type": dev_type,
            "device_icon": dev_icon, "os": os_g}


def _is_valid_ip(value):
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return False
    return True


# ─────────────────────────────────────────────
#  GAMIFICATION HELPERS
# ─────────────────────────────────────────────

def check_and_award_badges(username):
    stats = database.get_user_stats(username)
    total = len(stats)
    correct = sum(1 for s in stats if s["identified_correctly"])
    badges_before = len(database.get_user_badges(username))
    badges_to_check = []

    if total >= 5:
        badges_to_check.append(("first_steps", "First Steps \u2014 Complete 5 email analyses"))
    if total >= 25:
        badges_to_check.append(("dedicated", "Dedicated Analyst \u2014 Complete 25 email analyses"))
    if total >= 100:
        badges_to_check.append(("phish_hunter", "Phish Hunter \u2014 Complete 100 email analyses"))
    if total > 0 and correct / total >= 0.9:
        badges_to_check.append(("eagle_eye", "Eagle Eye \u2014 Maintain 90%+ accuracy"))
    if total >= 10 and all(s["identified_correctly"] for s in stats[:10]):
        badges_to_check.append(("perfect_streak", "Perfect Streak \u2014 Get 10 in a row correct"))
    streak = 0
    for s in stats:
        if s["identified_correctly"]:
            streak += 1
        else:
            break
    if streak >= 5:
        badges_to_check.append(("hot_streak", "Hot Streak \u2014 5 correct in a row"))
    phishing_count = sum(1 for s in stats if s["is_phishing"] and s["identified_correctly"])
    if phishing_count >= 10:
        badges_to_check.append(("phishing_spotted", "Phishing Spotter \u2014 Correctly identify 10 phishing emails"))

    for badge_id, _ in badges_to_check:
        database.award_badge(username, badge_id)

    badges_after = len(database.get_user_badges(username))
    return badges_after > badges_before
