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

import os
import json
import argparse
from pathlib import Path

from ingestion import IngestionEngine
from static_analyzer import StaticAnalyzer, CandidateFinding
from dynamic_analyzer import DynamicOrchestrator, DASTCandidateFinding
from ai_supervisor import AISupervisor
from reporter import generate_report, generate_markdown_report

def main():
    parser = argparse.ArgumentParser(description="AI Analysis Agent for Hybrid Vulnerability Scanning (SAST + DAST)")
    parser.add_argument("target_dir", nargs='?', default=None, help="Directory to scan (for SAST)")
    parser.add_argument("--target-url", default=None, help="URL to scan (for DAST, e.g., http://localhost:8080)")
    parser.add_argument("--dast-engines", default="wapiti", help="Comma-separated list of DAST engines to run (e.g., wapiti,nuclei,zap)")
    parser.add_argument("--output", default="vulnerability_report.pdf", help="Output PDF report path")
    parser.add_argument("--api-url", required=True, help="HTTPS endpoint of the LLM API (e.g., https://openrouter.ai/api/v1/chat/completions)")
    parser.add_argument("--zap-url", default="http://127.0.0.1:8081", help="URL of the OWASP ZAP Daemon (default: http://127.0.0.1:8081)")
    parser.add_argument("--zap-api-key", default="", help="API Key for the OWASP ZAP Daemon")
    parser.add_argument("--resume", default=None, help="Path to xsecurity_raw_findings.json to resume from (skips SAST/DAST)")
    
    # Optional explicitly forced modes
    parser.add_argument("-S", "--sast", action="store_true", help="Force SAST mode only")
    parser.add_argument("-D", "--dast", action="store_true", help="Force DAST mode only")
    parser.add_argument("-H", "--hybrid", action="store_true", help="Force Hybrid (SAST + DAST) mode")
    
    parser.add_argument("--model", required=True, help="Model name to use (e.g., anthropic/claude-3-haiku, llama3)")
    parser.add_argument("--api-key", required=True, help="API Key for the provider (use 'none' for local models with no auth)")
    args = parser.parse_args()

    if not args.target_dir and not args.target_url and not args.resume:
        print("Error: You must provide either a target directory (SAST), a --target-url (DAST), or --resume.")
        return

    print("==================================================")
    print("      X-SECURITY: Hybrid AI Vulnerability Scanner   ")
    print("==================================================")

    all_candidates = []

    if args.resume:
        print(f"\n[Phase 1 & 2] Bypassed! Resuming from: {args.resume}")
        try:
            with open(args.resume, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
            
            # Reconstruct objects
            for item in raw_data:
                if "rule_id" in item:
                    # It's a CandidateFinding (SAST)
                    all_candidates.append(CandidateFinding(**item))
                elif "vulnerability_type" in item:
                    # It's a DASTCandidateFinding (DAST)
                    all_candidates.append(DASTCandidateFinding(**item))
                    
            print(f"Loaded {len(all_candidates)} candidates successfully.")
        except Exception as e:
            print(f"Error loading resume file: {e}")
            return
    else:
        # Determine mode
        run_sast = False
        run_dast = False
        
        if args.hybrid:
            run_sast = True
            run_dast = True
        elif args.sast:
            run_sast = True
        elif args.dast:
            run_dast = True
        else:
            # Auto-mode
            if args.target_dir:
                run_sast = True
            if args.target_url:
                run_dast = True
                
        if run_sast and not args.target_dir:
            print("Error: SAST or Hybrid mode requires a target_dir.")
            return
            
        if run_dast and not args.target_url:
            print("Error: DAST or Hybrid mode requires a --target-url.")
            return

        if run_sast:
            target_path = Path(args.target_dir).absolute()
            if not target_path.exists() or not target_path.is_dir():
                print(f"Error: Target directory '{target_path}' does not exist.")
                return
                
            # Phase 1: Recon & Filtering
            print("\n[Phase 1] Ingestion and Reconnaissance (SAST)...")
            ingestion_engine = IngestionEngine(target_path)
            manifest = ingestion_engine.scan()
            if not manifest:
                print("No source files found to scan. Skipping SAST.")
            else:
                # Phase 2: Static Analysis (Parser & Orchestrator)
                print("\n[Phase 2] Static Analysis (Semgrep)...")
                analyzer = StaticAnalyzer(target_path)
                sast_candidates = analyzer.scan(rules_path="auto")
                all_candidates.extend(sast_candidates)

        if run_dast:
            print(f"\n[Phase 2.5] Dynamic Analysis (DAST) on {args.target_url}...")
            engines_list = [e.strip() for e in args.dast_engines.split(",")]
            orchestrator = DynamicOrchestrator(engines=engines_list, zap_url=args.zap_url, zap_api_key=args.zap_api_key)
            dast_candidates = orchestrator.scan_all(args.target_url)
            all_candidates.extend(dast_candidates)

        if not all_candidates:
            print("\nNo candidate vulnerabilities found during scans.")
            print("Generating empty report...")
            generate_report([], args.output)
            return

        # Intermediate Save: Raw Findings
        print("\n[Checkpoint] Saving raw candidate findings to 'xsecurity_raw_findings.json'...")
        try:
            with open("xsecurity_raw_findings.json", "w", encoding="utf-8") as f:
                json.dumps_obj = [getattr(c, '__dict__', str(c)) for c in all_candidates]
                json.dump(json.dumps_obj, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Failed to save raw findings: {e}")

    # Deduplicate candidates if any overlap occurred
    seen = set()
    deduped_candidates = []
    for c in all_candidates:
        key = (getattr(c, 'rule_id', None), getattr(c, 'file_path', None), getattr(c, 'start_line', None), getattr(c, 'vulnerability_type', None), getattr(c, 'target_url', None))
        if key not in seen:
            seen.add(key)
            deduped_candidates.append(c)
    all_candidates = deduped_candidates

    # Phase 3: Semantic Analysis (AI Supervisor)
    print(f"\n[Phase 3] Semantic Analysis (AI Critique) using {args.model} via {args.api_url}...")
    supervisor = AISupervisor(api_url=args.api_url, model_name=args.model, api_key=args.api_key)
    verified_findings = supervisor.evaluate_all(all_candidates)

    # Intermediate Save: Verified Findings
    print("\n[Checkpoint] Saving AI-verified findings to 'xsecurity_verified_findings.json'...")
    try:
        with open("xsecurity_verified_findings.json", "w", encoding="utf-8") as f:
            json.dumps_obj = [getattr(v, '__dict__', str(v)) for v in verified_findings]
            json.dump(json.dumps_obj, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"Warning: Failed to save verified findings: {e}")

    # Phase 4: Reporter
    print("\n[Phase 4] Generating Reports...")
    md_output = args.output.replace(".pdf", ".md")
    
    # 1. Sophisticated Markdown Report (Handles all UTF-8 safely)
    generate_markdown_report(verified_findings, md_output)
    
    # 2. PDF Report (Fallback, might crash on extreme payloads)
    try:
        generate_report(verified_findings, args.output)
    except Exception as e:
        print(f"\n[CRITICAL ERROR] PDF generation failed: {e}")
        print(f"-> Do not worry, your sophisticated technical report is safely saved in '{md_output}'.")
    
    print("\n==================================================")
    print(f"Scan complete. Found {len(verified_findings)} verified vulnerabilities.")
    print(f"Report available at: {args.output}")
    print("==================================================")

if __name__ == "__main__":
    main()
