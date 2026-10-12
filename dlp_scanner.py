#!/usr/bin/env python3
"""
Redact - Sensitive Content Scanner (Mini DLP)
Information and Cyber Security Lab - Micro-project 6:
'Use detectors within a rule to identify sensitive content'

Zero-dependency Python 3 CLI & Library implementing:
- Detectors: Aadhaar (Verhoeff), Credit Card (Luhn), PAN, Password, Email, Indian Phone, Custom Regex
- Overlap resolution & Priority ordering
- Rules Engine: Configurable thresholds, Actions (LOG, WARN, BLOCK)
- Risk Score Calculation (0-100)
- Checksum rejection logging
- Redaction generation (Blackout or Tagged tokens)
"""

import sys
import os
import re
import json
import argparse
from typing import List, Dict, Any, Tuple, Optional

# ==============================================================================
# 1. ALGORITHMS: VERHOEFF & LUHN CHECKSUMS
# ==============================================================================

# Verhoeff algorithm multiplication table d
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

# Verhoeff algorithm permutation table p
VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

def validate_verhoeff(num_str: str) -> bool:
    """Validate 12-digit Aadhaar number using Verhoeff checksum algorithm."""
    digits = [int(c) for c in str(num_str) if c.isdigit()]
    if len(digits) != 12:
        return False
    c = 0
    for i, digit in enumerate(reversed(digits)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]]
    return c == 0

def validate_luhn(num_str: str) -> bool:
    """Validate 13-19 digit Credit Card number using Luhn algorithm."""
    digits = [int(c) for c in str(num_str) if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += digit
    return total % 10 == 0

def mask_value(raw_val: str) -> str:
    """Mask value showing first 2 and last 2 characters."""
    raw_clean = raw_val.strip()
    if len(raw_clean) <= 4:
        return "****"
    return f"{raw_clean[:2]}{'*' * (len(raw_clean) - 4)}{raw_clean[-2:]}"

# ==============================================================================
# 2. DETECTOR DEFINITIONS
# ==============================================================================

DETECTORS_CONFIG = [
    {
        "id": "D1",
        "name": "Aadhaar",
        "tag": "AADHAAR",
        "regex": r"\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b",
        "validator": "verhoeff",
        "priority": 1,
        "color": "#FF007A"  # Neon Pink / Magenta
    },
    {
        "id": "D2",
        "name": "Credit card",
        "tag": "CARD",
        "regex": r"\b(?:\d[ -]?){13,19}\b",
        "validator": "luhn",
        "priority": 2,
        "color": "#00F0FF"  # Cyber Cyan
    },
    {
        "id": "D3",
        "name": "PAN",
        "tag": "PAN",
        "regex": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "validator": None,
        "priority": 3,
        "color": "#FFE600"  # Electric Yellow
    },
    {
        "id": "D4",
        "name": "Password",
        "tag": "PASSWORD",
        "regex": r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*([^\s,;]+)",
        "validator": None,
        "priority": 4,
        "color": "#FF3300"  # Blazing Red-Orange
    },
    {
        "id": "D5",
        "name": "Email",
        "tag": "EMAIL",
        "regex": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        "validator": None,
        "priority": 5,
        "color": "#39FF14"  # Neon Lime
    },
    {
        "id": "D6",
        "name": "Indian phone",
        "tag": "PHONE",
        "regex": r"\b(?:\+91[-\s]?|0)?[6-9]\d{9}\b",
        "validator": None,
        "priority": 6,
        "color": "#BF00FF"  # Electric Purple
    },
    {
        "id": "D7",
        "name": "Custom detector",
        "tag": "CUSTOM",
        "regex": None,
        "validator": None,
        "priority": 7,
        "color": "#FF9900"  # Neon Tangerine
    }
]

# Default Rules as per PRD Section 6.2 (R5)
DEFAULT_RULES = [
    {
        "id": "R1",
        "name": "Government ID leak",
        "detector_ids": ["D1", "D3"],  # Aadhaar, PAN
        "threshold": 1,
        "action": "BLOCK",
        "enabled": True
    },
    {
        "id": "R2",
        "name": "Payment data",
        "detector_ids": ["D2"],        # Credit card
        "threshold": 1,
        "action": "BLOCK",
        "enabled": True
    },
    {
        "id": "R3",
        "name": "Credentials",
        "detector_ids": ["D4"],        # Password
        "threshold": 1,
        "action": "BLOCK",
        "enabled": True
    },
    {
        "id": "R4",
        "name": "Bulk personal data",
        "detector_ids": ["D5", "D6"],  # Email, Indian phone
        "threshold": 5,
        "action": "WARN",
        "enabled": True
    },
    {
        "id": "R5",
        "name": "Custom keyword rule",
        "detector_ids": ["D7"],        # Custom detector
        "threshold": 1,
        "action": "WARN",
        "enabled": True
    }
]

# ==============================================================================
# 3. SCANNER ENGINE CLASS
# ==============================================================================

class RedactScanner:
    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None, custom_regex: Optional[str] = None):
        self.rules = rules if rules is not None else [dict(r) for r in DEFAULT_RULES]
        self.custom_regex = custom_regex
        self.detectors_map = {d["id"]: dict(d) for d in DETECTORS_CONFIG}
        if custom_regex:
            self.detectors_map["D7"]["regex"] = custom_regex

    def scan_text(self, text: str) -> Dict[str, Any]:
        """Scan input text for sensitive data and evaluate rules."""
        raw_candidates = []
        rejected_candidates = {
            "verhoeff": 0,
            "luhn": 0,
            "details": []
        }

        # 1. Run all detectors
        for det_id, det in sorted(self.detectors_map.items(), key=lambda x: x[1]["priority"]):
            pattern_str = det["regex"]
            if not pattern_str:
                continue

            try:
                flags = re.IGNORECASE if "(?i)" in pattern_str else 0
                pattern = re.compile(pattern_str, flags)
            except re.error as e:
                # Skip invalid regex
                continue

            for match in pattern.finditer(text):
                matched_text = match.group(0)
                start_idx = match.start()
                end_idx = match.end()

                # Special treatment for password: capture full line or matched key=val
                validator = det["validator"]
                is_valid = True

                if validator == "verhoeff":
                    clean_digits = re.sub(r"\D", "", matched_text)
                    if len(clean_digits) == 12 and validate_verhoeff(clean_digits):
                        is_valid = True
                    else:
                        is_valid = False
                        rejected_candidates["verhoeff"] += 1
                        rejected_candidates["details"].append({
                            "detector": "Aadhaar",
                            "reason": "Failed Verhoeff checksum",
                            "value": mask_value(matched_text),
                            "span": [start_idx, end_idx]
                        })

                elif validator == "luhn":
                    clean_digits = re.sub(r"\D", "", matched_text)
                    if 13 <= len(clean_digits) <= 19 and validate_luhn(clean_digits):
                        is_valid = True
                    else:
                        is_valid = False
                        rejected_candidates["luhn"] += 1
                        rejected_candidates["details"].append({
                            "detector": "Credit card",
                            "reason": "Failed Luhn checksum",
                            "value": mask_value(matched_text),
                            "span": [start_idx, end_idx]
                        })

                if is_valid:
                    raw_candidates.append({
                        "detector_id": det["id"],
                        "detector_name": det["name"],
                        "tag": det["tag"],
                        "priority": det["priority"],
                        "color": det["color"],
                        "value": matched_text,
                        "masked": mask_value(matched_text),
                        "start": start_idx,
                        "end": end_idx
                    })

        # 2. Overlap Resolution: Earlier detector in priority wins (PRD Section 6.1)
        # Sort candidates by start ascending, then priority ascending, then length descending
        raw_candidates.sort(key=lambda c: (c["start"], c["priority"], -(c["end"] - c["start"])))

        resolved_findings = []
        for candidate in raw_candidates:
            c_start = candidate["start"]
            c_end = candidate["end"]

            overlap = False
            for existing in resolved_findings:
                e_start = existing["start"]
                e_end = existing["end"]
                # Check interval intersection
                if max(c_start, e_start) < min(c_end, e_end):
                    overlap = True
                    break

            if not overlap:
                resolved_findings.append(candidate)

        # Sort findings strictly by start index
        resolved_findings.sort(key=lambda x: x["start"])

        # 3. Rule Evaluation
        # Count findings per detector
        detector_counts = {}
        for f in resolved_findings:
            d_id = f["detector_id"]
            detector_counts[d_id] = detector_counts.get(d_id, 0) + 1

        triggered_rules = []
        evaluated_rules = []
        max_action_rank = 0  # 0: CLEAN, 1: LOG, 2: WARN, 3: BLOCK
        rank_to_action = {0: "CLEAN", 1: "LOG", 2: "WARN", 3: "BLOCK"}
        action_ranks = {"CLEAN": 0, "LOG": 1, "WARN": 2, "BLOCK": 3}

        # Base weights per PRD Section 9.3: BLOCK 30, WARN 12, LOG 4
        action_weights = {"BLOCK": 30, "WARN": 12, "LOG": 4}
        total_risk_score = 0

        for rule in self.rules:
            if not rule.get("enabled", True):
                evaluated_rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "action": rule["action"],
                    "threshold": rule["threshold"],
                    "match_count": 0,
                    "triggered": False,
                    "status": "DISABLED"
                })
                continue

            rule_match_count = sum(detector_counts.get(d_id, 0) for d_id in rule["detector_ids"])
            is_triggered = rule_match_count >= rule["threshold"] and rule_match_count > 0

            rule_info = {
                "id": rule["id"],
                "name": rule["name"],
                "action": rule["action"],
                "threshold": rule["threshold"],
                "match_count": rule_match_count,
                "triggered": is_triggered,
                "status": "TRIGGERED" if is_triggered else "PASS"
            }
            evaluated_rules.append(rule_info)

            if is_triggered:
                triggered_rules.append(rule_info)
                # Compute risk weight: base weight + min(matches, 5) * 3
                act = rule["action"].upper()
                base_w = action_weights.get(act, 0)
                rule_risk = base_w + (min(rule_match_count, 5) * 3)
                total_risk_score += rule_risk

                # Update verdict rank
                rank = action_ranks.get(act, 0)
                if rank > max_action_rank:
                    max_action_rank = rank

        total_risk_score = min(100, total_risk_score)
        overall_verdict = rank_to_action[max_action_rank]

        # 4. Generate Redacted Text Formats
        # - Solid blackout bars of equal length
        # - Tagged placeholder tokens [DETECTOR REDACTED]
        blackout_text, tagged_text = self._generate_redactions(text, resolved_findings)

        return {
            "verdict": overall_verdict,
            "risk_score": total_risk_score,
            "findings_count": len(resolved_findings),
            "findings": resolved_findings,
            "rules_evaluated": evaluated_rules,
            "triggered_rules": triggered_rules,
            "rejections": {
                "total": rejected_candidates["verhoeff"] + rejected_candidates["luhn"],
                "aadhaar_verhoeff": rejected_candidates["verhoeff"],
                "credit_card_luhn": rejected_candidates["luhn"],
                "details": rejected_candidates["details"]
            },
            "redacted_blackout": blackout_text,
            "redacted_tagged": tagged_text,
            "text_length": len(text)
        }

    def _generate_redactions(self, text: str, findings: List[Dict[str, Any]]) -> Tuple[str, str]:
        """Produce solid blackout text and tagged placeholder text."""
        if not findings:
            return text, text

        blackout_chars = list(text)
        tagged_parts = []
        last_idx = 0

        for f in findings:
            start = f["start"]
            end = f["end"]
            tag = f["tag"]

            # Blackout replacement: exact character width in full block character '█'
            length = end - start
            for i in range(start, end):
                blackout_chars[i] = "█"

            # Tagged text
            tagged_parts.append(text[last_idx:start])
            tagged_parts.append(f"[{tag} REDACTED]")
            last_idx = end

        tagged_parts.append(text[last_idx:])

        return "".join(blackout_chars), "".join(tagged_parts)

# ==============================================================================
# 4. CLI INTERFACE
# ==============================================================================

def main():
    # Ensure Windows console can print UTF-8 characters like '█'
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description="Redact - Sensitive Content Scanner (Mini DLP CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dlp_scanner.py --text "My Aadhaar is 2345 6789 0124 and card is 4532 0151 1283 0366"
  python dlp_scanner.py --file confidential.txt
  python dlp_scanner.py --folder ./logs --json
  python dlp_scanner.py --file user.md --redact-tagged
        """
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", "-t", type=str, help="Direct text to scan")
    group.add_argument("--file", "-f", type=str, help="Path to single text file (.txt, .csv, .log, .json, .md)")
    group.add_argument("--folder", "-d", type=str, help="Path to folder to scan all supported text files")

    parser.add_argument("--custom-regex", "-c", type=str, default=None, help="User supplied custom regex pattern")
    parser.add_argument("--json", "-j", action="store_true", help="Output machine-readable JSON report")
    parser.add_argument("--redact-blackout", action="store_true", help="Print blackout redacted text")
    parser.add_argument("--redact-tagged", action="store_true", help="Print tagged redacted text")
    parser.add_argument("--bulk-threshold", type=int, default=5, help="Bulk personal data threshold (default: 5)")

    args = parser.parse_args()

    # Configure scanner
    rules = [dict(r) for r in DEFAULT_RULES]
    for r in rules:
        if r["id"] == "R4":
            r["threshold"] = args.bulk_threshold

    scanner = RedactScanner(rules=rules, custom_regex=args.custom_regex)

    # 1. Folder Scan Mode
    if args.folder:
        if not os.path.isdir(args.folder):
            print(f"Error: Folder '{args.folder}' does not exist.", file=sys.stderr)
            sys.exit(1)

        supported_exts = {".txt", ".csv", ".log", ".json", ".md"}
        folder_results = []
        overall_highest_verdict = "CLEAN"
        action_ranks = {"CLEAN": 0, "LOG": 1, "WARN": 2, "BLOCK": 3}

        for root, _, files in os.walk(args.folder):
            for file in files:
                _, ext = os.path.splitext(file)
                if ext.lower() in supported_exts:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read(200000)
                        res = scanner.scan_text(content)
                        res["file"] = file_path
                        folder_results.append(res)
                        if action_ranks[res["verdict"]] > action_ranks[overall_highest_verdict]:
                            overall_highest_verdict = res["verdict"]
                    except Exception as ex:
                        folder_results.append({
                            "file": file_path,
                            "error": str(ex),
                            "verdict": "ERROR"
                        })

        if args.json:
            print(json.dumps({
                "mode": "folder_scan",
                "folder": args.folder,
                "overall_verdict": overall_highest_verdict,
                "scanned_files_count": len(folder_results),
                "results": folder_results
            }, indent=2))
        else:
            print("=" * 70)
            print("  REDACT // SENSITIVE CONTENT SCANNER (FOLDER REPORT)")
            print("=" * 70)
            print(f"  Target Folder   : {args.folder}")
            print(f"  Scanned Files   : {len(folder_results)}")
            print(f"  Overall Verdict : {overall_highest_verdict}")
            print("-" * 70)
            for item in folder_results:
                if "error" in item:
                    print(f"  [ERROR] {item['file']}: {item['error']}")
                else:
                    print(f"  [{item['verdict']}] (Risk: {item['risk_score']}/100, Findings: {item['findings_count']}) -> {item['file']}")
            print("=" * 70)

        sys.exit(2 if overall_highest_verdict == "BLOCK" else (1 if overall_highest_verdict == "WARN" else 0))

    # 2. Single File or Text Mode
    raw_text = ""
    target_name = "direct_input"

    if args.file:
        if not os.path.isfile(args.file):
            print(f"Error: File '{args.file}' not found.", file=sys.stderr)
            sys.exit(1)
        target_name = args.file
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            raw_text = f.read(200000)
    else:
        raw_text = args.text

    result = scanner.scan_text(raw_text)

    if args.redact_blackout:
        print(result["redacted_blackout"])
        sys.exit(0)

    if args.redact_tagged:
        print(result["redacted_tagged"])
        sys.exit(0)

    if args.json:
        result["target"] = target_name
        print(json.dumps(result, indent=2))
    else:
        print("=" * 68)
        print("  REDACT // DLP CONTENT SCANNER AUDIT REPORT")
        print("=" * 68)
        print(f"  Target Input    : {target_name}")
        print(f"  Content Length  : {result['text_length']} chars")
        print(f"  Verdict Stamp   : [{result['verdict']}]")
        print(f"  Risk Meter      : {result['risk_score']}/100")
        print(f"  Valid Findings  : {result['findings_count']}")
        print(f"  False Positives : {result['rejections']['total']} rejected (Verhoeff: {result['rejections']['aadhaar_verhoeff']}, Luhn: {result['rejections']['credit_card_luhn']})")
        print("-" * 68)

        if result["triggered_rules"]:
            print("  TRIGGERED POLICY RULES:")
            for tr in result["triggered_rules"]:
                print(f"    - [{tr['action']}] {tr['name']} (Count: {tr['match_count']}, Threshold: {tr['threshold']})")
        else:
            print("  TRIGGERED POLICY RULES: None (All rules passed)")

        if result["findings"]:
            print("-" * 68)
            print("  SENSITIVE DATA FINDINGS:")
            for idx, f in enumerate(result["findings"], 1):
                print(f"    {idx:02d}. [{f['detector_name']}] Value: {f['masked']}  Span: [{f['start']}:{f['end']}]")

        print("=" * 68)

    # Exit code based on verdict
    if result["verdict"] == "BLOCK":
        sys.exit(2)
    elif result["verdict"] == "WARN":
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
