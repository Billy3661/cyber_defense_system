from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
import os

OUTPUT = os.path.join(os.path.dirname(__file__), "Securix_Overview.pdf")

doc = SimpleDocTemplate(
    OUTPUT,
    pagesize=letter,
    topMargin=0.75*inch,
    bottomMargin=0.75*inch,
    leftMargin=0.85*inch,
    rightMargin=0.85*inch,
)

styles = getSampleStyleSheet()

NAVY = colors.HexColor("#0f172a")
BLUE = colors.HexColor("#3b82f6")
DARK_BG = colors.HexColor("#1e293b")
GRAY = colors.HexColor("#64748b")
LIGHT_BG = colors.HexColor("#f1f5f9")
RED = colors.HexColor("#ef4444")
GREEN = colors.HexColor("#22c55e")

styles.add(ParagraphStyle(
    "DocTitle", parent=styles["Title"],
    fontSize=28, leading=34, textColor=NAVY,
    spaceAfter=6, fontName="Helvetica-Bold",
))
styles.add(ParagraphStyle(
    "Subtitle", parent=styles["Normal"],
    fontSize=13, leading=18, textColor=GRAY,
    spaceAfter=20, fontName="Helvetica",
))
styles.add(ParagraphStyle(
    "SectionHead", parent=styles["Heading1"],
    fontSize=16, leading=22, textColor=NAVY,
    spaceBefore=18, spaceAfter=8, fontName="Helvetica-Bold",
))
styles.add(ParagraphStyle(
    "SubHead", parent=styles["Heading2"],
    fontSize=12, leading=16, textColor=BLUE,
    spaceBefore=12, spaceAfter=4, fontName="Helvetica-Bold",
))
styles.add(ParagraphStyle(
    "BodyText2", parent=styles["Normal"],
    fontSize=10, leading=15, textColor=colors.HexColor("#1e293b"),
    spaceAfter=6, fontName="Helvetica", alignment=TA_JUSTIFY,
))
styles.add(ParagraphStyle(
    "BulletItem", parent=styles["Normal"],
    fontSize=10, leading=14, textColor=colors.HexColor("#1e293b"),
    spaceAfter=4, fontName="Helvetica",
    leftIndent=18, bulletIndent=6,
))
styles.add(ParagraphStyle(
    "TableCell", parent=styles["Normal"],
    fontSize=9, leading=13, textColor=colors.HexColor("#1e293b"),
    fontName="Helvetica",
))
styles.add(ParagraphStyle(
    "TableCellBold", parent=styles["Normal"],
    fontSize=9, leading=13, textColor=NAVY,
    fontName="Helvetica-Bold",
))

story = []

# ── Title ──
story.append(Paragraph("Securix", styles["DocTitle"]))
story.append(Paragraph("Cyber Defense System &mdash; Executive Overview", styles["Subtitle"]))
story.append(HRFlowable(width="100%", thickness=2, color=BLUE, spaceAfter=16))

# ── The Problem ──
story.append(Paragraph("The Problem", styles["SectionHead"]))
story.append(Paragraph(
    "People are being scammed at an alarming rate. Phishing emails, malicious URLs, "
    "fake websites, and data breaches cost individuals and organizations billions every year. "
    "Most victims lack the tools or knowledge to identify threats before it is too late. "
    "By the time they realize, credentials are stolen, accounts are drained, and identities "
    "are compromised. Over 80% of successful cyberattacks exploit the human element.",
    styles["BodyText2"]
))

# ── What Securix Does ──
story.append(Paragraph("What Securix Does", styles["SectionHead"]))
story.append(Paragraph(
    "Securix is a real-time threat intelligence platform that lets anyone &mdash; not just "
    "security professionals &mdash; scan, detect, and understand cyber threats before they "
    "cause harm. It consolidates multiple intelligence sources into a single, accessible interface.",
    styles["BodyText2"]
))

# ── Core Capabilities ──
story.append(Paragraph("Core Capabilities", styles["SectionHead"]))

capabilities = [
    ("URL & Domain Threat Analysis",
     "Scans any URL against VirusTotal (90+ antivirus engines), Google Safe Browsing, "
     "URLhaus, Cloudflare Radar, and AbuseIPDB in parallel. Detects phishing indicators "
     "including suspicious keywords, abuse TLDs, URL obfuscation, IP-based hosts, and "
     "1,455+ known URL shorteners. Provides WHOIS registrant data, DNS records, and "
     "SSL certificate details for domain attribution. A heuristic scoring engine catches "
     "threats even before API confirmation."),
    ("File Malware Detection",
     "Upload files for hash-based scanning against VirusTotal, cross-referenced against "
     "a local malware signature database covering known ransomware, trojans, and RATs."),
    ("IP Intelligence",
     "Retrieves geolocation, ISP, hosting provider, WHOIS ownership data, DNS record "
     "analysis, and SSL certificate inspection for any IP address."),
    ("Email Breach Checking",
     "Checks if an email address has been compromised in known data breaches via "
     "HaveIBeenPwned. Password breach checking uses k-anonymity so no password ever "
     "leaves the user's device."),
    ("Email Header Analysis",
     "Parses raw email headers to detect spoofing. Verifies SPF, DKIM, and DMARC "
     "authentication results. Identifies suspicious routing and origin mismatches."),
    ("AI Cybersecurity Assistant",
     "A conversational AI powered by Groq that answers security questions in real time "
     "with context-aware responses about threats, best practices, and incident response. "
     "Includes persistent chat history."),
    ("Phishing Awareness Simulator",
     "Simulates realistic phishing emails for training. Gamified learning with streaks, "
     "badges, and leaderboards. Tracks accuracy, response times, and red flag identification. "
     "Generates debriefs explaining what users missed."),
]

for title, desc in capabilities:
    story.append(Paragraph(title, styles["SubHead"]))
    story.append(Paragraph(desc, styles["BodyText2"]))

# ── Gaps Filled ──
story.append(Paragraph("Gaps It Fills", styles["SectionHead"]))

gap_data = [
    [Paragraph("<b>Gap</b>", styles["TableCellBold"]),
     Paragraph("<b>How Securix Addresses It</b>", styles["TableCellBold"])],
    [Paragraph("Tools are fragmented &mdash; users need 5+ separate services to check one URL",
               styles["TableCell"]),
     Paragraph("Consolidates 6+ threat intelligence APIs into a single scan",
               styles["TableCell"])],
    [Paragraph("Technical barrier &mdash; existing tools require expertise to interpret",
               styles["TableCell"]),
     Paragraph("Plain-language verdicts with color-coded risk levels",
               styles["TableCell"])],
    [Paragraph("No training &mdash; people click phishing links because they do not know what to look for",
               styles["TableCell"]),
     Paragraph("Built-in phishing simulator with real-time education",
               styles["TableCell"])],
    [Paragraph("Reactive, not proactive &mdash; people only check after they have been harmed",
               styles["TableCell"]),
     Paragraph("One-click scanning before clicking any link",
               styles["TableCell"])],
    [Paragraph("No breach awareness &mdash; users do not know their data has been leaked",
               styles["TableCell"]),
     Paragraph("Proactive breach and password exposure checking",
               styles["TableCell"])],
]

gap_table = Table(gap_data, colWidths=[3.0*inch, 3.4*inch])
gap_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, -1), 9),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("TOPPADDING", (0, 0), (-1, -1), 6),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
]))
story.append(gap_table)

# ── Advantages ──
story.append(Paragraph("Key Advantages", styles["SectionHead"]))

advantages = [
    "<b>Multi-source intelligence</b> &mdash; Cross-referencing multiple APIs reduces false positives that single-source tools miss.",
    "<b>Zero configuration</b> &mdash; Works immediately with just a free VirusTotal API key.",
    "<b>User authentication</b> &mdash; Personal dashboards, scan history, and individual API key management.",
    "<b>Admin panel</b> &mdash; Manage users, malware signatures, and monitor system usage.",
    "<b>Mobile responsive</b> &mdash; Works on phones where most phishing attacks are encountered.",
    "<b>Self-hosted</b> &mdash; No data sent to third-party dashboards; full control over sensitive scan data.",
    "<b>Educational by design</b> &mdash; Every scan teaches the user what to look for, reducing future risk.",
]

for adv in advantages:
    story.append(Paragraph(adv, styles["BulletItem"], bulletText="&#x25CF;"))

# ── Bottom Line ──
story.append(Spacer(1, 12))
story.append(HRFlowable(width="100%", thickness=1, color=BLUE, spaceAfter=12))
story.append(Paragraph("Bottom Line", styles["SectionHead"]))
story.append(Paragraph(
    "Securix turns cybersecurity from a specialist discipline into an accessible, everyday "
    "practice. It does not just detect threats &mdash; it trains people to recognize them, "
    "reducing the human risk factor that accounts for over 80% of successful cyberattacks.",
    styles["BodyText2"]
))

story.append(Spacer(1, 24))
story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY, spaceAfter=8))
story.append(Paragraph(
    "<i>Securix &mdash; Cyber Defense System | Educational &amp; Awareness Platform</i>",
    ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=GRAY, alignment=TA_CENTER)
))

doc.build(story)
print(f"PDF generated: {OUTPUT}")
