# ==============================================================================
# X-SECURITY - Hybrid AI-Powered Vulnerability Scanner
# 
# Author: Oussama Elattaoui (GitHub: oussama-zs)
# Institution: Ecole des Sciences de l'Information (ESI), Rabat
# Project: Projet de Fin d'Annee (PFA) 2025/2026
# Company: CGX (Creative Generated Experience)
#
# This software is part of an academic project.
# Unauthorized copying, modification, or distribution without credit is prohibited.
# ==============================================================================

from fpdf import FPDF
from typing import List
from datetime import datetime
import os

from ai_supervisor import VerifiedFinding

class PDFReporter(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'AI Analysis Agent - Vulnerability Report', 0, 1, 'C')
        self.ln(5)
        
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_report(findings: List[VerifiedFinding], output_path: str = "report.pdf"):
    print(f"Generating PDF report with {len(findings)} verified findings...")
    
    pdf = PDFReporter()
    pdf.add_page()
    
    # Metadata
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Date generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(0, 10, f"Total verified findings: {len(findings)}", ln=True)
    pdf.ln(10)
    
    if not findings:
        pdf.set_font("Arial", 'I', 12)
        pdf.cell(0, 10, "No confirmed vulnerabilities found.", ln=True)
    
    for i, finding in enumerate(findings, 1):
        # Vulnerability Title
        pdf.set_font("Arial", 'B', 14)
        pdf.set_text_color(200, 0, 0) if str(finding.severity).upper() in ["HIGH", "CRITICAL"] else pdf.set_text_color(200, 100, 0)
        title = f"{i}. [{finding.analysis_type}] {finding.vulnerability_name or finding.rule_id} ({finding.severity})"
        pdf.cell(0, 10, title, ln=True)
        pdf.set_text_color(0, 0, 0)
        
        # Details
        pdf.set_font("Arial", 'B', 11)
        pdf.cell(30, 8, "Target:", border=0)
        pdf.set_font("Arial", '', 11)
        
        if getattr(finding, "analysis_type", "SAST") == "SAST":
            target_str = f"{finding.file_path}:{finding.line_number}"
        else:
            target_str = finding.file_path
            
        pdf.cell(0, 8, target_str, ln=True)
        
        if finding.cwe:
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(30, 8, "CWE:", border=0)
            pdf.set_font("Arial", '', 11)
            pdf.cell(0, 8, finding.cwe, ln=True)
            
        pdf.set_font("Arial", 'B', 11)
        pdf.cell(30, 8, "Confidence:", border=0)
        pdf.set_font("Arial", '', 11)
        pdf.cell(0, 8, finding.confidence, ln=True)
        
        pdf.ln(2)
        
        # Description
        pdf.set_font("Arial", 'B', 11)
        pdf.cell(0, 8, "Description:", ln=True)
        pdf.set_font("Arial", '', 11)
        pdf.multi_cell(0, 6, finding.description or "No description provided.")
        pdf.ln(2)
        
        # AI Rationale
        pdf.set_font("Arial", 'B', 11)
        pdf.cell(0, 8, "AI Rationale:", ln=True)
        pdf.set_font("Arial", 'I', 11)
        pdf.multi_cell(0, 6, finding.ai_rationale)
        pdf.ln(2)
        
        # Suggestion
        pdf.set_font("Arial", 'B', 11)
        pdf.cell(0, 8, "Suggested Correction:", ln=True)
        pdf.set_font("Arial", '', 11)
        pdf.multi_cell(0, 6, finding.suggested_correction or "No suggestion provided.")
        
        pdf.ln(10)
        
    try:
        pdf.output(output_path)
        print(f"PDF report saved to {output_path}")
    except Exception as e:
        print(f"Error saving PDF report (possibly due to unsupported UTF-8 characters like emojis): {e}")

def generate_markdown_report(findings: List[VerifiedFinding], output_path: str = "vulnerability_report.md"):
    print(f"Generating Markdown report with {len(findings)} verified findings...")
    
    lines = []
    lines.append("# 🛡️ AI Analysis Agent - Vulnerability Report")
    lines.append(f"**Date generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Total verified findings:** {len(findings)}")
    lines.append("---")
    
    if not findings:
        lines.append("*No confirmed vulnerabilities found.*")
    else:
        for i, finding in enumerate(findings, 1):
            severity_icon = "🔴" if str(finding.severity).upper() in ["HIGH", "CRITICAL"] else "🟠"
            lines.append(f"## {i}. {severity_icon} [{finding.analysis_type}] {finding.vulnerability_name or finding.rule_id} ({finding.severity})")
            
            target_str = f"`{finding.file_path}:{finding.line_number}`" if getattr(finding, "analysis_type", "SAST") == "SAST" else f"`{finding.file_path}`"
            
            lines.append(f"- **Target:** {target_str}")
            if finding.cwe:
                lines.append(f"- **CWE:** {finding.cwe}")
            lines.append(f"- **Confidence:** {finding.confidence}")
            lines.append("")
            
            lines.append("### Description")
            lines.append(finding.description or "No description provided.")
            lines.append("")
            
            lines.append("### AI Rationale")
            lines.append(f"> {finding.ai_rationale}")
            lines.append("")
            
            lines.append("### Suggested Correction")
            lines.append(finding.suggested_correction or "No suggestion provided.")
            lines.append("---")
            
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"Markdown report saved to {output_path}")
    except Exception as e:
        print(f"Error saving Markdown report: {e}")

if __name__ == "__main__":
    # Test script
    dummy_finding = VerifiedFinding(
        rule_id="hardcoded-secret",
        vulnerability_name="Hardcoded API Key",
        severity="HIGH",
        cwe="CWE-798",
        description="A hardcoded API key was found in the source code.",
        suggested_correction="Move the API key to an environment variable.",
        file_path="src/main.js",
        line_number=42,
        analysis_type="SAST",
        confidence="High",
        is_false_positive=False,
        ai_rationale="The code contains a direct assignment of a high-entropy string to a variable named API_KEY."
    )
    generate_report([dummy_finding], "test_report.pdf")
