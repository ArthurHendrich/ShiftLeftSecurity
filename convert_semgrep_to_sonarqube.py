#!/usr/bin/env python3
import json
import sys
from typing import Dict, List, Optional
import os

def map_severity_with_confidence(severity: str, confidence: str) -> str:
    severity_map = {
        "ERROR": "BLOCKER",
        "WARNING": "MAJOR",
        "INFO": "MINOR"
    }
    base_severity = severity_map.get(severity.upper(), "MAJOR")
    
    confidence = confidence.upper()
    if confidence == "HIGH" and base_severity not in ["BLOCKER"]:
        base_severity = "CRITICAL"
    elif confidence == "LOW" and base_severity == "MINOR":
        base_severity = "INFO"
    
    return base_severity

def map_type(metadata: Dict) -> str:
    security_indicators = [
        "security", "vuln", "injection", "xss", "csrf", "ssrf", "auth", 
        "secret", "password", "cred", "priv", "exploit", "rce", "remote",
        "command", "exec", "shell", "overflow", "bypass", "brute", "force",
        "dos", "denial", "service", "access", "control", "permission"
    ]
    
    check_id = metadata.get("rule_id", "").lower()
    category = metadata.get("category", "").lower()
    
    # Always return VULNERABILITY for security-related findings
    if category == "security":
        return "VULNERABILITY"
    
    if any(indicator in check_id or indicator in category for indicator in security_indicators):
        return "VULNERABILITY"
    
    if metadata.get("cwe") or metadata.get("owasp"):
        return "VULNERABILITY"
    
    if metadata.get("vulnerability_class"):
        return "VULNERABILITY"
    
    tags = metadata.get("tags", [])
    if any(indicator in tag.lower() for tag in tags for indicator in security_indicators):
        return "VULNERABILITY"
    
    message = metadata.get("message", "").lower()
    if any(indicator in message for indicator in security_indicators):
        return "VULNERABILITY"
    
    if "bug" in category:
        return "BUG"
    
    return "CODE_SMELL"

def create_sonarqube_issue(finding: Dict, file_cache: Dict[str, List[str]]) -> Dict:
    """
    Create a SonarQube "issue" object from a single Semgrep finding,
    clamping columns to avoid out-of-range errors in SonarQube.
    """
    metadata = finding.get("extra", {}).get("metadata", {})
    extra = finding.get("extra", {})
    rule_id = finding["check_id"]
    
    filepath = finding["path"]
    message = extra.get("message", "No description provided")
    
    start = finding.get("start", {})
    end = finding.get("end", {})

    # Default line/col = 1 if missing
    if isinstance(start, dict):
        start_line = start.get("line", 1)
        start_col = start.get("col", 1)
    else:
        start_line = 1
        start_col = 1
        
    if isinstance(end, dict):
        end_line = end.get("line", start_line)
        end_col = end.get("col", start_col)
    else:
        end_line = start_line
        end_col = start_col

    # Load file content if not in cache
    if filepath not in file_cache:
        try:
            with open(filepath, "r") as f:
                file_cache[filepath] = f.readlines()
        except Exception:
            # If we can't read the file, treat it as empty
            file_cache[filepath] = []

    lines = file_cache[filepath]

    # We clamp columns to ensure they don't exceed line length
    if lines and 0 < start_line <= len(lines) and 0 < end_line <= len(lines):
        start_line_content = lines[start_line - 1].rstrip('\n\r')
        end_line_content   = lines[end_line - 1].rstrip('\n\r')
        
        # Debug prints to confirm line length
        # (these go to stderr so they won't break the JSON output)
        print(
            f"DEBUG: File={filepath} line={start_line} "
            f"start_col={start_col}, end_line={end_line}, end_col={end_col} "
            f"start_line_length={len(start_line_content)}, end_line_length={len(end_line_content)}",
            file=sys.stderr
        )
        
        # Always clamp, even for "django-no-csrf-token"
        start_col = max(1, min(start_col, len(start_line_content)))
        if end_line == start_line:
            # If start and end lines are the same, ensure end_col >= start_col
            end_col = max(start_col, min(end_col, len(end_line_content)))
        else:
            # If different lines, clamp independently
            end_col = max(1, min(end_col, len(end_line_content)))
    else:
        # If no valid line or content, default everything
        start_line = 1
        start_col = 1
        end_line = 1
        end_col = 1

    # Build tags
    tags = ["security"]
    cwe_data = metadata.get("cwe")
    if cwe_data:
        cwe_values = cwe_data if isinstance(cwe_data, list) else [cwe_data]
        for c in cwe_values:
            cwe_id = c.split(':')[0].split()[0].lower()  # "cwe-601"
            tags.append(cwe_id)

    owasp_data = metadata.get("owasp")
    if owasp_data:
        owasp_values = owasp_data if isinstance(owasp_data, list) else [owasp_data]
        for o in owasp_values:
            owasp_id = o.split(':')[0].strip().lower()  # "a01"
            tags.append(f"owasp-{owasp_id}")

    return {
        "ruleId": rule_id,
        "effortMinutes": 30,
        "primaryLocation": {
            "message": message,
            "filePath": filepath,
            "textRange": {
                "startLine": start_line,
                "startColumn": start_col,
                "endLine": end_line,
                "endColumn": end_col
            }
        },
        "secondaryLocations": [],
        "tags": tags
    }

def main():
    """
    Reads Semgrep JSON from stdin or from a file (if provided),
    then converts to a SonarQube external issues report with
    top-level "rules" and "issues".
    """
    try:
        if len(sys.argv) > 1:
            with open(sys.argv[1], 'r') as f:
                input_data = json.load(f)
        else:
            input_data = json.load(sys.stdin)

        file_cache = {}
        findings = input_data.get("results", [])
        
        # Gather all unique rules
        rules = []
        processed_rule_ids = set()
        
        for finding in findings:
            rule_id = finding["check_id"]
            if rule_id not in processed_rule_ids:
                metadata = finding.get("extra", {}).get("metadata", {})
                extra = finding.get("extra", {})
                
                # Create a descriptive name from the last part of the rule ID
                name = rule_id.split(".")[-1] 
                name = name.replace("-", " ").replace("_", " ")
                name = " ".join(word.capitalize() for word in name.split())
                
                severity = map_severity_with_confidence(
                    extra.get("severity", "WARNING"),
                    metadata.get("confidence", "MEDIUM")
                )
                
                rule = {
                    "id": rule_id,
                    "name": name,
                    "description": extra.get("message", "No description provided"),
                    "engineId": "semgrep",
                    "cleanCodeAttribute": "TRUSTWORTHY",
                    "type": map_type(metadata),
                    "severity": severity,
                    "impacts": [
                        {
                            "softwareQuality": "SECURITY",
                            "severity": "HIGH" if severity in ["BLOCKER", "CRITICAL"] else "MEDIUM"
                        }
                    ]
                }
                rules.append(rule)
                processed_rule_ids.add(rule_id)
        
        # Build issues
        sonarqube_issues = []
        for finding in findings:
            try:
                issue = create_sonarqube_issue(finding, file_cache)
                sonarqube_issues.append(issue)
            except Exception as e:
                print(f"Error converting finding {finding.get('check_id', 'unknown')}: {str(e)}", file=sys.stderr)
                continue

        # Output final JSON
        output = {"rules": rules, "issues": sonarqube_issues}
        json.dump(output, sys.stdout, indent=2)
        print(f"Successfully converted {len(sonarqube_issues)} issues", file=sys.stderr)

    except Exception as e:
        print(f"Error in main: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
