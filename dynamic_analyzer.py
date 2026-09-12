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
import logging
import requests
from dataclasses import dataclass
from typing import List
from pathlib import Path

# Dedicated DAST logger configured to write detailed logs to dast_scan.log
dast_logger = logging.getLogger("xsecurity.dast")
dast_logger.setLevel(logging.DEBUG)

# File handler for dast_scan.log
if not dast_logger.handlers:
    fh = logging.FileHandler("dast_scan.log", mode="w", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    fh.setFormatter(formatter)
    dast_logger.addHandler(fh)

def log_msg(msg: str, level: str = "info"):
    """Prints message to stdout and logs to dast_scan.log."""
    print(msg)
    if level == "error":
        dast_logger.error(msg)
    elif level == "warning":
        dast_logger.warning(msg)
    else:
        dast_logger.info(msg)

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
    def __init__(self, cookie: str = ""):
        self.cookie = cookie

    def scan(self, target_url: str) -> List[DASTCandidateFinding]:
        findings = []
        output_file = "wapiti_output.json"
        
        if os.path.exists(output_file):
            try:
                os.remove(output_file)
            except Exception:
                pass
            
        log_msg(f"[Wapiti] Starting scan on {target_url}...")
        
        cmd = [
            "wapiti",
            "-u", target_url,
            "-f", "json",
            "-o", output_file,
            "-m", "sql,xss,file,crlf,exec,ssrf",
            "--max-scan-time", "120"
        ]
        if self.cookie:
            cmd.extend(["--header", f"Cookie: {self.cookie}"])
            dast_logger.info(f"[Wapiti] Injected session cookie into requests.")
        
        dast_logger.info(f"[Wapiti] Command: {' '.join(cmd)}")
        
        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", env=env)
            dast_logger.info(f"[Wapiti] Return code: {proc.returncode}")
            if proc.stdout:
                dast_logger.debug(f"[Wapiti STDOUT]:\n{proc.stdout}")
            if proc.stderr:
                dast_logger.info(f"[Wapiti STDERR]:\n{proc.stderr}")
            
            if not os.path.exists(output_file):
                log_msg(f"[Wapiti] Notice: No output JSON generated (Code {proc.returncode}). Check 'dast_scan.log' for details.", level="warning")
                if proc.stderr:
                    dast_logger.error(f"[Wapiti Stderr Details]: {proc.stderr}")
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
                        http_response_snippet="Response snippet inferred by Wapiti reflection."
                    )
                    findings.append(finding)
                    
            dast_logger.info(f"[Wapiti] Successfully parsed {len(findings)} findings.")
                    
        except FileNotFoundError:
            log_msg("[Wapiti] Error: 'wapiti' command not found. Is it installed in PATH?", level="error")
        except Exception as e:
            log_msg(f"[Wapiti] Error during execution/parsing: {e}", level="error")
            
        return findings

class NucleiEngine(DASTEngine):
    def __init__(self, cookie: str = ""):
        self.cookie = cookie

    def scan(self, target_url: str) -> List[DASTCandidateFinding]:
        findings = []
        output_file = "nuclei_output.json"
        
        if os.path.exists(output_file):
            try:
                os.remove(output_file)
            except Exception:
                pass
            
        log_msg(f"[Nuclei] Starting scan on {target_url}...")
        
        cmd = [
            "nuclei",
            "-u", target_url,
            "-json-export", output_file,
            "-t", "cves/,vulnerabilities/"
        ]
        if self.cookie:
            cmd.extend(["-H", f"Cookie: {self.cookie}"])
            dast_logger.info(f"[Nuclei] Injected session cookie header.")
        
        dast_logger.info(f"[Nuclei] Command: {' '.join(cmd)}")
        
        try:
            env = os.environ.copy()
            proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
            dast_logger.info(f"[Nuclei] Return code: {proc.returncode}")
            if proc.stdout:
                dast_logger.debug(f"[Nuclei STDOUT]:\n{proc.stdout}")
            if proc.stderr:
                dast_logger.info(f"[Nuclei STDERR]:\n{proc.stderr}")
            
            if not os.path.exists(output_file):
                log_msg(f"[Nuclei] Notice: No findings exported for {target_url}.", level="info")
                return findings
            
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
                            http_response_snippet=str(vuln.get("response", "N/A"))[:500]
                        )
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue
                        
            dast_logger.info(f"[Nuclei] Successfully parsed {len(findings)} findings.")
                        
        except FileNotFoundError:
            log_msg("[Nuclei] Error: 'nuclei' command not found in PATH.", level="error")
        except Exception as e:
            log_msg(f"[Nuclei] Error parsing results: {e}", level="error")
            
        return findings

class ZAPEngine(DASTEngine):
    def __init__(self, proxy_url="http://127.0.0.1:8081", api_key="", cookie: str = ""):
        self.proxy_url = proxy_url.rstrip('/')
        self.api_key = api_key
        self.cookie = cookie
        self.headers = {"X-ZAP-API-Key": self.api_key} if self.api_key else {}
        
    def scan(self, target_url: str) -> List[DASTCandidateFinding]:
        findings = []
        log_msg(f"[ZAP] Connecting to daemon at {self.proxy_url} to attack {target_url}...")
        dast_logger.info(f"[ZAP] Target: {target_url}, Daemon: {self.proxy_url}")
        
        try:
            # Check daemon accessibility
            ver_res = requests.get(f"{self.proxy_url}/JSON/core/view/version/?apikey={self.api_key}", headers=self.headers, timeout=5)
            if ver_res.status_code == 403:
                log_msg(f"[ZAP] Auth Error (403 Forbidden): ZAP exige une clé API. Lancez ZAP avec: zaproxy -daemon -port 8081 -config api.disablekey=true OU fournissez l'argument --zap-api-key <VOTRE_CLE>", level="error")
                return findings
            elif ver_res.status_code != 200:
                log_msg(f"[ZAP] Error: Daemon returned status {ver_res.status_code} ({ver_res.text})", level="error")
                return findings
            log_msg(f"[ZAP] Daemon online (Version: {ver_res.json().get('version', 'OK')})")
            
            # Configure Session Cookie if provided
            if self.cookie:
                try:
                    requests.get(
                        f"{self.proxy_url}/JSON/replacer/action/addRule/?description=AuthCookie&enabled=true&matchTypeCode=4&matchString=Cookie&replacement={self.cookie}&apikey={self.api_key}",
                        headers=self.headers,
                        timeout=5
                    )
                    log_msg(f"[ZAP] Authenticated session cookie configured for scan.")
                except Exception as e:
                    dast_logger.warning(f"[ZAP] Could not set replacer cookie rule: {e}")
            
            # 1. Spider
            log_msg("[ZAP] Running Spider crawler...")
            res = requests.get(f"{self.proxy_url}/JSON/spider/action/scan/?url={target_url}&apikey={self.api_key}", headers=self.headers, timeout=10)
            if res.status_code != 200:
                log_msg(f"[ZAP] Error triggering spider: {res.text}", level="error")
                return findings
            scan_id = res.json().get("scan")
            
            while True:
                stat = requests.get(f"{self.proxy_url}/JSON/spider/view/status/?scanId={scan_id}&apikey={self.api_key}", headers=self.headers).json()
                if stat.get("status") == "100":
                    log_msg("[ZAP] Spider crawler complete (100%).")
                    break
                time.sleep(2)
                
            # 2. Active Scan
            log_msg("[ZAP] Running Active Scan...")
            res = requests.get(f"{self.proxy_url}/JSON/ascan/action/scan/?url={target_url}&apikey={self.api_key}", headers=self.headers, timeout=10)
            scan_id = res.json().get("scan")
            
            while True:
                stat = requests.get(f"{self.proxy_url}/JSON/ascan/view/status/?scanId={scan_id}&apikey={self.api_key}", headers=self.headers).json()
                status_int = int(stat.get("status", 0))
                if status_int >= 100:
                    log_msg("[ZAP] Active Scan complete (100%).")
                    break
                print(f"[ZAP] Active Scan progress: {status_int}%")
                time.sleep(5)
                
            # 3. Retrieve Alerts
            log_msg("[ZAP] Retrieving Alerts...")
            res = requests.get(f"{self.proxy_url}/JSON/core/view/alerts/?baseurl={target_url}&apikey={self.api_key}", headers=self.headers)
            alerts = res.json().get("alerts", [])
            dast_logger.info(f"[ZAP] Retrieved {len(alerts)} raw alerts from daemon.")
            
            for vuln in alerts:
                severity = vuln.get("risk", "Medium")
                if severity == "Informational":
                    continue
                    
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
                
            dast_logger.info(f"[ZAP] Filtered to {len(findings)} non-informational findings.")
                
        except requests.exceptions.ConnectionError:
            log_msg(f"[ZAP] Notice: Could not connect to ZAP Daemon at {self.proxy_url}. Make sure ZAP is running with API enabled on port 8081.", level="warning")
        except Exception as e:
            log_msg(f"[ZAP] Error during ZAP scan: {e}", level="error")
            
        return findings

class DynamicOrchestrator:
    def __init__(self, engines: List[str], zap_url: str = "http://127.0.0.1:8081", zap_api_key: str = "", cookie: str = ""):
        self.cookie = cookie
        self.engines = []
        for eng in engines:
            e = eng.lower().strip()
            if e == "wapiti":
                self.engines.append(WapitiEngine(cookie=cookie))
            elif e == "nuclei":
                self.engines.append(NucleiEngine(cookie=cookie))
            elif e == "zap":
                self.engines.append(ZAPEngine(proxy_url=zap_url, api_key=zap_api_key, cookie=cookie))
            else:
                log_msg(f"Warning: Unknown DAST engine '{eng}'", level="warning")
                
    def scan_all(self, target_url: str) -> List[DASTCandidateFinding]:
        # 1. URL Normalization
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
            log_msg(f"[DAST] Auto-prefixed URL scheme -> {target_url}")
            
        log_msg("--------------------------------------------------")
        log_msg(f"[DAST Orchestrator] Target: {target_url}")
        log_msg(f"[DAST Orchestrator] Engines: {[e.__class__.__name__ for e in self.engines]}")
        if self.cookie:
            log_msg(f"[DAST Orchestrator] Authentication: Active (Cookie: {self.cookie[:20]}...)")
        log_msg(f"[DAST Orchestrator] Detailed logs -> dast_scan.log")
        log_msg("--------------------------------------------------")
        
        # 2. Pre-flight connectivity check with session Cookie
        headers = {"Cookie": self.cookie} if self.cookie else {}
        try:
            probe = requests.get(target_url, headers=headers, timeout=10, allow_redirects=True)
            log_msg(f"[DAST Pre-flight] Target is reachable (HTTP {probe.status_code}).")
            if self.cookie:
                log_msg(f"[DAST Pre-flight] Authenticated session active! Probed successfully with Cookie.")
            if probe.history:
                log_msg(f"[DAST Pre-flight] Redirected to: {probe.url}")
        except Exception as e:
            log_msg(f"[DAST Pre-flight WARNING] Unable to reach {target_url}: {e}", level="warning")
            log_msg(f"[DAST Pre-flight WARNING] Verify that the target server is started and listening.", level="warning")

        all_findings = []
        for engine in self.engines:
            engine_name = engine.__class__.__name__
            try:
                findings = engine.scan(target_url)
                all_findings.extend(findings)
                log_msg(f"[{engine_name}] Result: {len(findings)} vulnerability candidate(s) collected.")
            except Exception as e:
                log_msg(f"[DAST Orchestrator] Error running {engine_name}: {e}", level="error")
                
        log_msg("--------------------------------------------------")
        log_msg(f"[DAST Orchestrator] Total dynamic findings collected: {len(all_findings)}")
        log_msg("--------------------------------------------------")
        return all_findings
