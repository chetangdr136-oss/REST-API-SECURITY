"""PDF report generation."""
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from xml.sax.saxutils import escape

def make_pdf(result):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("REST API Security Assessment Report", styles["Title"]),
        Spacer(1, 10),
        Paragraph(f"<b>Target:</b> {escape(result.get('target', ''))}", styles["BodyText"]),
        Paragraph(f"<b>Assessment time:</b> {escape(result.get('timestamp', ''))}", styles["BodyText"]),
        Spacer(1, 14)
    ]
    rows = [["Check", "Severity", "Status", "Evidence", "Recommendation"]]
    for f in result.get("findings", []):
        rows.append([
            Paragraph(escape(str(f.get("check", ""))), styles["BodyText"]),
            Paragraph(escape(str(f.get("severity", ""))), styles["BodyText"]),
            Paragraph(escape(str(f.get("status", ""))), styles["BodyText"]),
            Paragraph(escape(str(f.get("evidence", ""))), styles["BodyText"]),
            Paragraph(escape(str(f.get("recommendation", ""))), styles["BodyText"])
        ])
    table = Table(rows, repeatRows=1, colWidths=[75, 48, 65, 145, 155])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#203864")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.4, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 7),
        ("PADDING", (0,0), (-1,-1), 5),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#eef2f7")])
    ]))
    story.append(table)
    story.append(Spacer(1, 14))
    story.append(Paragraph(
        "Disclaimer: This is an educational baseline assessment. Findings are indicators, not proof. "
        "Manual verification and authorized, endpoint-specific testing are required.",
        styles["Italic"]
    ))
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
