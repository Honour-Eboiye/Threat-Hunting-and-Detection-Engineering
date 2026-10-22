import re
from docx import Document

# Robust regex for IPv4 (0-255 boundary checks)
IPV4_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

# Regex covering standard and compressed IPv6 formats
IPV6_REGEX = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}\b'

COMBINED_IP_REGEX = re.compile(f"{IPV4_REGEX}|{IPV6_REGEX}")
REDACTION_TOKEN = "[REDACTED_IP]"

def redact_text(text: str) -> str:
    """Redacts only the last two octets of IPv4. Fully redacts IPv6."""
    def replace_match(m):
        ip = m.group(0)
        # Check if it's IPv4 by trying to split into 4 octets
        parts = ip.split('.')
        if len(parts) == 4:
            # Keep first two octets, redact last two
            return f"{parts[0]}.{parts[1]}.[REDACTED].[REDACTED]"
        else:
            # IPv6: redact fully
            return "[REDACTED_IP]"
    
    return COMBINED_IP_REGEX.sub(replace_match, text)

def redact_paragraph(paragraph):
    """
    Redacts text within a paragraph while preserving run-level formatting.
    Note: For runs where an IP is split across formatting boundaries, 
    we perform a fallback check across the entire paragraph text.
    """
    if not COMBINED_IP_REGEX.search(paragraph.text):
        return

    # Check run by run to preserve formatting (bold, italic, color)
    matched_in_runs = False
    for run in paragraph.runs:
        if COMBINED_IP_REGEX.search(run.text):
            run.text = redact_text(run.text)
            matched_in_runs = True

    # If the IP address was split across adjacent XML runs, redact at paragraph level
    if not matched_in_runs and COMBINED_IP_REGEX.search(paragraph.text):
        paragraph.text = redact_text(paragraph.text)

def sanitize_document(input_file: str, output_file: str):
    """
    Loads a DOCX document, scans body paragraphs and tables,
    redacts all detected IP addresses, and saves the output.
    """
    doc = Document(input_file)

    # 1. Redact body paragraphs
    for p in doc.paragraphs:
        redact_paragraph(p)

    # 2. Redact text inside tables
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    redact_paragraph(p)

    doc.save(output_file)
    print(f"[+] Successfully sanitized '{input_file}' -> Saved to '{output_file}'")

if __name__ == "__main__":
    # Example usage:
    input_doc = "Threat Hunt Report.docx"
    output_doc = "Threat_Hunt_Report_redacted.docx"
    
    sanitize_document(input_doc, output_doc)