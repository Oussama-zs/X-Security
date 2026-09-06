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

import json
import subprocess
import os
import time
import requests
from dataclasses import dataclass
from typing import List
from pathlib import Path

@dataclass
class DASTCandidateFinding:
    engine: str
    vulnerability_type: str
    severity: str
    target_url: str
    payload: str
    http_request: str
    http_response_snippet: str

class DASTEngine:
    def scan(self, target_url: str) -> List[DASTCandidateFinding]:
        raise NotImplementedError("Each DAST engine must implement scan()")

class WapitiEngine(DASTEngine):
    def scan(self, target_url: str) -> List[DASTCandidateFinding]:
        findings = []
        output_file = "wapiti_output.json"
        
        if os.path.exists(output_file):
            os.remove(output_file)
            
        print(f"[Wapiti] Starting scan on {target_url}...")
        
        cmd = [
            "wapiti",
            "-u", target_url,
            "-f", "json",
            "-o", output_file,
            "-m", "sql,xss,file,crlf,exec,ssrf", # Added exec and ssrf to match our dummy app
            "--max-scan-time", "120" 
        ]
        
        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            
            subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", env=env)
            
            if not os.path.exists(output_file):
                print("[Wapiti] Error: No output file generated. Scan may have failed.")
                return findings
                
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            vulnerabilities = data.get("vulnerabilities", {})
            for vuln_type, vuln_list in vulnerabilities.items():
                for vuln in vuln_list:
                    http_req = vuln.get("http_request", "N/A")
                    payload = vuln.get("parameter", "") + " = " + vuln.get("info", "")
                    
                    raw_level = vuln.get("level", 2)
                    if str(raw_level) == "1": severity_str = "Low"
                    elif str(raw_level) == "2": severity_str = "Medium"
                    elif str(raw_level) == "3": severity_str = "High"
                    elif str(raw_level) == "4": severity_str = "Critical"
                    else: severity_str = str(raw_level)

                    finding = DASTCandidateFinding(
                        engine="Wapiti",
                        vulnerability_type=vuln_type,
                        severity=severity_str,
                        target_url=vuln.get("path", target_url),
                        payload=payload,
                        http_request=http_req,
                        http_response_snippet="Response snippet not fully captured by Wapiti by default. AI must infer from payload reflection."
                    )
                    findings.append(finding)
                    
        except FileNotFoundError:
            print("[Wapiti] Error: wapiti command not found. Is it installed in PATH?")
        except Exception as e:
            print(f"[Wapiti] Error parsing results: {e}")
            
        return findings

class NucleiEngine(DASTEngine):
    def scan(self, target_url: str) -> List[DASTCandidateFinding]:
        findings = []
        output_file = "nuclei_output.json"
        
        if os.path.exists(output_file):
            os.remove(output_file)
            
        print(f"[Nuclei] Starting scan on {target_url}...")
        
        cmd = [
            "nuclei",
            "-u", target_url,
            "-json-export", output_file,
            "-t", "cves/,vulnerabilities/"
        ]
        
        try:
            env = os.environ.copy()
            subprocess.run(cmd, capture_output=True, text=True, env=env)
            
            if not os.path.exists(output_file):
                print("[Nuclei] Warning: No output file generated. Scan may have found nothing, or Nuclei failed.")
                return findings
            
            # Nuclei exports JSON Lines format (one JSON object per line)
            with open(output_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        vuln = json.loads(line)
                        info = vuln.get("info", {})
                        
                        finding = DASTCandidateFinding(
                            engine="Nuclei",
                            vulnerability_type=info.get("name", "Unknown Nuclei Vuln"),
                            severity=str(info.get("severity", "Medium")).capitalize(),
                            target_url=vuln.get("matched-at", target_url),
                            payload=vuln.get("extracted-results", [""])[0] if vuln.get("extracted-results") else "N/A",
                            http_request=vuln.get("request", "N/A"),
                            http_response_snippet=str(vuln.get("response", "N/A"))[:500]  # truncate huge responses
                        )
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue
                        
        except FileNotFoundError:
            print("[Nuclei] Error: nuclei command not found. Please download Nuclei and add it to your PATH.")
        except Exception as e:
            print(f"[Nuclei] Error parsing results: {e}")
            
        return findings

class ZAPEngine(DASTEngine):
    def __init__(self, proxy_url="http://127.0.0.1:8081", api_key=""):
        self.proxy_url = proxy_url
        self.api_key = api_key
        
    def scan(self, target_url: str) -> List[DASTCandidateFinding]:
        findings = []
        print(f"[ZAP] Starting scan on {target_url} via Daemon {self.proxy_url}...")
        
        try:
            # 1. Spider
            print("[ZAP] Running Spider...")
            res = requests.get(f"{self.proxy_url}/JSON/spider/action/scan/?url={target_url}&apikey={self.api_key}", timeout=5)
            if res.status_code != 200:
                print(f"[ZAP] Error triggering spider: {res.text}")
                return findings
            scan_id = res.json().get("scan")
            
            while True:
                stat = requests.get(f"{self.proxy_url}/JSON/spider/view/status/?scanId={scan_id}&apikey={self.api_key}").json()
                if stat.get("status") == "100":
                    break
                time.sleep(2)
                
            # 2. Active Scan
            print("[ZAP] Running Active Scan...")
            res = requests.get(f"{self.proxy_url}/JSON/ascan/action/scan/?url={target_url}&apikey={self.api_key}")
            scan_id = res.json().get("scan")
            
            while True:
                stat = requests.get(f"{self.proxy_url}/JSON/ascan/view/status/?scanId={scan_id}&apikey={self.api_key}").json()
                status_int = int(stat.get("status", 0))
                if status_int >= 100:
                    break
                print(f"[ZAP] Active Scan progress: {status_int}%")
                time.sleep(5)
                
            # 3. Retrieve Alerts
            print("[ZAP] Retrieving Alerts...")
            res = requests.get(f"{self.proxy_url}/JSON/core/view/alerts/?baseurl={target_url}&apikey={self.api_key}")
            alerts = res.json().get("alerts", [])
            
            for vuln in alerts:
                severity = vuln.get("risk", "Medium")
                if severity == "Informational":
                    continue # Skip low level noise
                    
                finding = DASTCandidateFinding(
                    engine="ZAP",
                    vulnerability_type=vuln.get("alert", "Unknown ZAP Vuln"),
                    severity=severity,
                    target_url=vuln.get("url", target_url),
                    payload=vuln.get("param", "") + " = " + vuln.get("attack", ""),
                    http_request="Method: " + vuln.get("method", "GET"),
                    http_response_snippet=vuln.get("evidence", "No evidence provided by ZAP API.")
                )
                findings.append(finding)
                
        except requests.exceptions.ConnectionError:
            print(f"[ZAP] Error: Could not connect to ZAP Daemon at {self.proxy_url}. Make sure ZAP is running on port 8081.")
        except Exception as e:
            print(f"[ZAP] Error during ZAP scan: {e}")
            
        return findings

class DynamicOrchestrator:
    def __init__(self, engines: List[str], zap_url: str = "http://127.0.0.1:8081", zap_api_key: str = ""):
        """
        engines: list of engine names e.g. ["wapiti", "nuclei", "zap"]
        zap_url: URL of the ZAP proxy/daemon
        zap_api_key: API key for the ZAP daemon
        """
        self.engines = []
        for eng in engines:
            e = eng.lower().strip()
            if e == "wapiti":
                self.engines.append(WapitiEngine())
            elif e == "nuclei":
                self.engines.append(NucleiEngine())
            elif e == "zap":
                self.engines.append(ZAPEngine(proxy_url=zap_url, api_key=zap_api_key))
            else:
                print(f"Warning: Unknown DAST engine '{eng}'")
                
    def scan_all(self, target_url: str) -> List[DASTCandidateFinding]:
        all_findings = []
        for engine in self.engines:
            try:
                findings = engine.scan(target_url)
                all_findings.extend(findings)
            except Exception as e:
                print(f"Error running {engine.__class__.__name__}: {e}")
                
        return all_findings
