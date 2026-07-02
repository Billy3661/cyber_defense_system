import os
import subprocess
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def create_flowchart():
    dot_content = """
    digraph G {
        rankdir=TB;
        node [shape=box, style=filled, fillcolor="#f8fafc", color="#3b82f6", fontname="Helvetica", fontcolor="#0f172a"];
        edge [color="#94a3b8", fontname="Helvetica", fontsize=10];
        
        UI [label="Securix Web UI", fillcolor="#3b82f6", fontcolor="white", shape=box3d];
        API [label="Flask Backend API"];
        VT [label="VirusTotal API", shape=cylinder, fillcolor="#10b981", fontcolor="white"];
        Scanner [label="Security Scanner\\n(Heuristics)"];
        NetDiscover [label="Network Auto-Discovery\\n(iwgetid & ping sweep)"];
        PortScanner [label="Deep Port Scanner"];
        
        UI -> API [label=" Upload/URL/Host Data"];
        API -> VT [label=" Live Lookup (Optional)"];
        API -> Scanner [label=" Pattern Matching"];
        API -> NetDiscover [label=" Trigger Scan"];
        NetDiscover -> PortScanner [label=" Found Hosts"];
        
        VT -> API [label=" Threat Reports"];
        Scanner -> API [label=" Phishing/Malware Flags"];
        PortScanner -> API [label=" Open Ports & Risks"];
        
        API -> UI [label=" JSON Results"];
    }
    """
    with open("flowchart.dot", "w") as f:
        f.write(dot_content)
    subprocess.run(["dot", "-Tpng", "-Gdpi=150", "flowchart.dot", "-o", "flowchart.png"])

def create_pdf():
    create_flowchart()
    
    pdf_filename = "Securix_Overview.pdf"
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.HexColor("#3b82f6"),
        alignment=1,
        spaceAfter=20
    )
    
    heading_style = ParagraphStyle(
        'HeadingStyle',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=16,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=10,
        spaceBefore=15
    )
    
    body_style = ParagraphStyle(
        'BodyStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        textColor=colors.HexColor("#334155"),
        spaceAfter=10,
        leading=14
    )

    story = []
    
    story.append(Paragraph("Securix", title_style))
    story.append(Paragraph("Advanced Security Diagnostics & Threat Analysis Platform", ParagraphStyle('Subtitle', parent=title_style, fontSize=14, textColor=colors.gray)))
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("System Overview", heading_style))
    intro_text = "Securix is a comprehensive cybersecurity platform designed to analyze URLs, scan suspicious files, discover network vulnerabilities, and educate users against modern phishing attacks. It combines local heuristic analysis with real-time threat intelligence from VirusTotal."
    story.append(Paragraph(intro_text, body_style))
    
    story.append(Paragraph("System Architecture Flow", heading_style))
    if os.path.exists("flowchart.png"):
        img = Image("flowchart.png", width=400, height=300)
        img.hAlign = 'CENTER'
        story.append(img)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("Core Capabilities", heading_style))
    
    features = [
        ["Feature", "Description"],
        ["URL Scanner", "Analyzes links for phishing indicators, excessive subdomains, and malicious payloads using heuristic scoring."],
        ["File Sandbox", "Inspects uploaded files for malicious signatures and structural anomalies, supporting live VirusTotal lookups."],
        ["Network Discovery", "Auto-detects the local Wi-Fi/LAN subnet, probes active hosts, and performs deep port scanning for security risks."],
        ["Email Analyzer", "Parses raw email headers to verify SPF, DKIM, and DMARC records to detect spoofing and impersonation."],
        ["Breach Checker", "Cross-references user credentials against HaveIBeenPwned API to identify historical data breaches."],
        ["Phishing Lab", "An interactive mock email client that trains users to spot phishing red flags and social engineering tactics."]
    ]
    
    t = Table(features, colWidths=[130, 350])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#3b82f6")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 12),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#f8fafc")),
        ('TEXTCOLOR', (0,1), (-1,-1), colors.HexColor("#334155")),
        ('ALIGN', (0,1), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,1), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("Security Assurances", heading_style))
    arch_text = "The platform is built on a lightweight Flask backend paired with a reactive frontend. API keys and sensitive user configurations are securely stored in a local SQLite database and retrieved dynamically. Threat scanning logic operates securely on the host, ensuring that internal network topology and proprietary files are analyzed safely."
    story.append(Paragraph(arch_text, body_style))
    
    doc.build(story)

create_pdf()
