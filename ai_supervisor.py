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
import re
import time
import requests
from dataclasses import dataclass
from typing import List, Union

from static_analyzer import CandidateFinding
from dynamic_analyzer import DASTCandidateFinding

@dataclass
class VerifiedFinding:
    rule_id: str
    vulnerability_name: str
    severity: str
    cwe: str
    description: str
    suggested_correction: str
    file_path: str
    line_number: int
    analysis_type: str # 'SAST' or 'DAST'
    confidence: str # High, Medium, Low
    is_false_positive: bool
    ai_rationale: str

class AISupervisor:
    def __init__(self, api_url: str, model_name: str, api_key: str):
        """
        Initializes a neutral AI Supervisor.
        Communicates with ANY LLM provider via standard HTTPS REST API calls.
        """
        self.api_url = api_url
        self.model_name = model_name
        self.api_key = api_key
        
    def _build_sast_prompt(self, candidate: CandidateFinding) -> str:
        return f"""
You are an expert Application Security Penetration Tester and Code Reviewer.
Your task is to analyze a "Candidate Finding" flagged by a SAST (Static Analysis) tool and determine if it is a TRUE POSITIVE (an actual, exploitable or dangerous vulnerability) or a FALSE POSITIVE (test code, safe usage, benign string, etc).

Here are the details of the candidate finding:
- Rule ID: {candidate.rule_id}
- Original Severity: {candidate.severity}
- File Path: {candidate.file_path}
- Line Number: {candidate.start_line}

Code Context (the finding is within this block):
```
{candidate.code_snippet}
```

CRITIQUE PHASE:
Before giving your final verdict, argue against this finding. Is it reachable? Is it test code? Is it properly sanitized elsewhere? Is it a dummy literal?
**CRITICAL INSTRUCTION**: Do NOT dismiss the finding just because the application or file is named "dummy", "test", or "demo". Treat all code as production code for the purpose of this analysis. If there is a real technical flaw (like SQLi or XSS), you MUST mark it as a TRUE POSITIVE (`is_false_positive`: false).

VERDICT:
After your critique, provide your final assessment. It is critical that your output is pure JSON matching this exact schema:
{{
    "is_false_positive": boolean,
    "confidence": "High" | "Medium" | "Low",
    "ai_rationale": "Brief summary of your critique and why it is or isn't a false positive",
    "vulnerability_name": "Human readable name of the vuln (if true positive, else empty string)",
    "cwe": "CWE-XXX (if true positive, else empty string)",
    "description": "Detailed description of the risk (if true positive, else empty string)",
    "suggested_correction": "How to fix the code (if true positive, else empty string)"
}}
"""

    def _build_dast_prompt(self, candidate: DASTCandidateFinding) -> str:
        return f"""
You are an expert Application Security Penetration Tester.
Your task is to analyze a "Candidate Finding" flagged by a DAST (Dynamic Analysis) tool and determine if it is a TRUE POSITIVE (a verified runtime exploit) or a FALSE POSITIVE (the scanner misinterpreted a 500 error or safe reflection).

Here are the details of the dynamic finding:
- Engine: {candidate.engine}
- Vulnerability Type: {candidate.vulnerability_type}
- Target URL: {candidate.target_url}
- Payload Injected: {candidate.payload}
- Severity: {candidate.severity}

HTTP Request Sent:
```
{candidate.http_request}
```

HTTP Response Snippet / Scanner Context:
```
{candidate.http_response_snippet}
```

CRITIQUE PHASE:
Argue against this finding. Did the server actually process the payload dangerously, or did it safely block/encode it? Could this just be a generic 500 error masquerading as a vulnerability? 
**CRITICAL INSTRUCTION**: If the HTTP Response Snippet is missing or says "Response snippet not fully captured", you MUST trust the DAST engine's verification and mark it as a TRUE POSITIVE (`is_false_positive`: false). DAST tools actively exploit the vulnerability, so their findings are highly accurate.

VERDICT:
Provide your final assessment. Your output MUST be pure JSON matching this exact schema:
{{
    "is_false_positive": boolean,
    "confidence": "High" | "Medium" | "Low",
    "ai_rationale": "Brief summary of your critique",
    "vulnerability_name": "Human readable name (e.g., Reflected XSS)",
    "cwe": "CWE-XXX",
    "description": "Detailed description of the runtime risk",
    "suggested_correction": "How to fix the server-side code"
}}
"""

    def _call_llm_api(self, prompt: str) -> str:
        """
        Generic HTTPS POST request to the LLM API, supporting both OpenAI-compat and Anthropic natively.
        """
        is_anthropic = "api.anthropic.com" in self.api_url
        headers = {"Content-Type": "application/json"}
        
        if self.api_key and self.api_key.lower() != "none":
            if is_anthropic:
                headers["x-api-key"] = self.api_key
                headers["anthropic-version"] = "2023-06-01"
            else:
                headers["Authorization"] = f"Bearer {self.api_key}"
                
        if is_anthropic:
            payload = {
                "model": self.model_name,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 2048
            }
        else:
            payload = {
                "model": self.model_name,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "response_format": {"type": "json_object"}
            }
            
        response = None
        for attempt in range(3):
            try:
                response = requests.post(self.api_url, headers=headers, json=payload, timeout=60)
                if response.status_code == 200:
                    break
                elif response.status_code == 429:
                    print(f"    -> [AI Rate Limit] Waiting 10s before retry (attempt {attempt+1}/3)...")
                    time.sleep(10)
                else:
                    raise RuntimeError(f"API Error ({response.status_code}): {response.text}")
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if attempt < 2:
                    print(f"    -> [Network Glitch] Connection issue ({e}). Retrying in 5s (attempt {attempt+1}/3)...")
                    time.sleep(5)
                else:
                    raise e
                    
        if response is None or response.status_code != 200:
            raise RuntimeError(f"API Error: Failed after 3 attempts")
            
        result = response.json()
        
        if is_anthropic:
            content = result["content"][0]["text"]
        else:
            content = result["choices"][0]["message"]["content"]
            
        # Clean up potential markdown formatting that Claude might add
        content = content.strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
            
        return content.strip()

    def _extract_json(self, raw_content: str) -> dict:
        """Extracts and parses the JSON verdict from the LLM output with high resilience."""
        content = raw_content.strip()
        
        # 1. Direct parsing if the entire response is clean JSON
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

        # 2. Markdown fenced code blocks: ```json ... ``` or ``` ... ```
        code_blocks = re.findall(r'```(?:json)?\s*([\s\S]*?)\s*```', content)
        for block in code_blocks:
            clean_block = block.strip()
            try:
                data = json.loads(clean_block)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass

        # 3. Locate the JSON object containing the expected key "is_false_positive"
        pos = content.find('"is_false_positive"')
        if pos != -1:
            start_idx = content.rfind('{', 0, pos)
            if start_idx != -1:
                depth = 0
                in_string = False
                escape = False
                for idx in range(start_idx, len(content)):
                    char = content[idx]
                    if escape:
                        escape = False
                        continue
                    if char == '\\':
                        escape = True
                        continue
                    if char == '"':
                        in_string = not in_string
                        continue
                    if not in_string:
                        if char == '{':
                            depth += 1
                        elif char == '}':
                            depth -= 1
                            if depth == 0:
                                candidate_str = content[start_idx:idx+1]
                                try:
                                    data = json.loads(candidate_str)
                                    if isinstance(data, dict):
                                        return data
                                except Exception:
                                    break

        # 4. Fallback: Search for any { ... } block containing "is_false_positive"
        for match in re.finditer(r'\{[^{}]*"is_false_positive"[\s\S]*?\}', content):
            try:
                data = json.loads(match.group(0))
                if isinstance(data, dict):
                    return data
            except Exception:
                continue

        raise ValueError(f"No valid JSON structure found in AI response: {content[:120]}...")

    def evaluate_candidate(self, candidate: Union[CandidateFinding, DASTCandidateFinding]) -> VerifiedFinding:
        """Sends the candidate to the generic LLM API and parses the structured response."""
        if isinstance(candidate, CandidateFinding):
            prompt = self._build_sast_prompt(candidate)
            rule_id = candidate.rule_id
            file_path = candidate.file_path
            line_number = candidate.start_line
            severity = candidate.severity
            analysis_type = "SAST"
        else:
            prompt = self._build_dast_prompt(candidate)
            rule_id = candidate.vulnerability_type
            file_path = candidate.target_url
            line_number = 0
            severity = candidate.severity
            analysis_type = "DAST"
        
        try:
            raw_content = self._call_llm_api(prompt)
            data = self._extract_json(raw_content)
            
            # Safely parse string booleans like "false" to boolean False
            is_fp_raw = data.get("is_false_positive", True)
            if isinstance(is_fp_raw, str):
                is_fp = is_fp_raw.lower() == "true"
            else:
                is_fp = bool(is_fp_raw)
                
            return VerifiedFinding(
                rule_id=rule_id,
                vulnerability_name=data.get("vulnerability_name", ""),
                severity=severity,
                cwe=data.get("cwe", ""),
                description=data.get("description", ""),
                suggested_correction=data.get("suggested_correction", ""),
                file_path=file_path,
                line_number=line_number,
                analysis_type=analysis_type,
                confidence=data.get("confidence", "Low"),
                is_false_positive=is_fp,
                ai_rationale=data.get("ai_rationale", "")
            )
        except Exception as e:
            print(f"    -> [CRITICAL ERROR] AI Parsing or API failed: {e}")
            return VerifiedFinding(
                rule_id=rule_id,
                vulnerability_name=f"Unverified {rule_id} (AI Error)",
                severity=severity,
                cwe="Unknown",
                description="The AI supervisor failed to analyze this finding due to an API or parsing error.",
                suggested_correction="Manual verification required.",
                file_path=file_path,
                line_number=line_number,
                analysis_type=analysis_type,
                confidence="Low",
                is_false_positive=False, # Keep it so it's not lost
                ai_rationale=f"AI Error: {e}"
            )

    def evaluate_all(self, candidates: List[Union[CandidateFinding, DASTCandidateFinding]]) -> List[VerifiedFinding]:
        """Evaluates a list of candidates and returns only the True Positives."""
        verified_findings = []
        print(f"Supervisor evaluating {len(candidates)} candidates via {self.api_url}...")
        
        for idx, candidate in enumerate(candidates):
            identifier = candidate.rule_id if isinstance(candidate, CandidateFinding) else candidate.vulnerability_type
            target = candidate.file_path if isinstance(candidate, CandidateFinding) else candidate.target_url
            print(f"  [{idx+1}/{len(candidates)}] AI analyzing {identifier} in {target}...")
            verified = self.evaluate_candidate(candidate)
            
            if not verified.is_false_positive:
                print(f"    -> [VERIFIED] {verified.vulnerability_name}")
                verified_findings.append(verified)
            else:
                print(f"    -> [DISCARDED] False Positive. Rationale: {verified.ai_rationale}")
                
        return verified_findings
