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

import subprocess
import json
from dataclasses import dataclass
from typing import List
from pathlib import Path

@dataclass
class CandidateFinding:
    rule_id: str
    message: str
    severity: str
    file_path: str
    start_line: int
    end_line: int
    code_snippet: str

class StaticAnalyzer:
    def __init__(self, root_path: str):
        self.root_path = Path(root_path).absolute()
        
    def _extract_snippet(self, file_path: str, start_line: int, end_line: int, context_lines: int = 5) -> str:
        """Extracts the finding and some surrounding context for the LLM."""
        full_path = self.root_path / file_path
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            # 1-indexed to 0-indexed, with context padding
            start_idx = max(0, start_line - 1 - context_lines)
            end_idx = min(len(lines), end_line + context_lines)
            
            return "".join(lines[start_idx:end_idx])
        except Exception as e:
            return f"<Error extracting snippet: {e}>"

    def scan(self, target_path: str = ".", rules_path: str = "auto") -> List[CandidateFinding]:
        """Runs semgrep on the target path using specified rules."""
        findings = []
        
        # Run semgrep with specified config (auto pulls standard security/bug rules)
        # We request JSON output to parse it easily
        cmd = [
            "semgrep", 
            "scan", 
            f"--config={rules_path}", 
            "--json", 
            target_path
        ]
        
        print(f"Running Semgrep on {target_path} (this might take a moment)...")
        
        try:
            # We run it with cwd=self.root_path so relative paths align
            # Explicitly specify utf-8 encoding to avoid Windows charmap decode errors
            result = subprocess.run(cmd, cwd=self.root_path, capture_output=True, text=True, encoding="utf-8")
            
            # Semgrep exits with 1 if it finds issues, which is normal for us.
            # If it exits with a different code (e.g. 2 for fatal error) and no stdout, it failed.
            if result.returncode != 0 and result.returncode != 1 and not result.stdout:
                 print(f"Semgrep failed to run: {result.stderr}")
                 return []
                 
            # Parse the JSON output
            data = json.loads(result.stdout)
            
            for match in data.get("results", []):
                file_path = match.get("path")
                start_line = match.get("start", {}).get("line")
                end_line = match.get("end", {}).get("line")
                
                snippet = self._extract_snippet(file_path, start_line, end_line)
                
                finding = CandidateFinding(
                    rule_id=match.get("check_id"),
                    message=match.get("extra", {}).get("message"),
                    severity=match.get("extra", {}).get("severity"),
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    code_snippet=snippet
                )
                findings.append(finding)
                
        except FileNotFoundError:
            print("Error: Semgrep is not installed or not in PATH. Please run `pip install semgrep`.")
        except json.JSONDecodeError:
            print("Error parsing Semgrep output. It may not have returned valid JSON.")
            print(result.stdout)
            
        return findings

if __name__ == "__main__":
    # Test on the dummy project with custom rules
    analyzer = StaticAnalyzer(".")
    candidates = analyzer.scan("dummy_project", rules_path="custom_rules.yaml")
    
    print(f"\nFound {len(candidates)} candidates.")
    for c in candidates:
        print(f"[{c.severity}] {c.rule_id} in {c.file_path}:{c.start_line}")
        print(f"Message: {c.message}")
        print(f"Snippet Context:\n{c.code_snippet}")
        print("-" * 40)
