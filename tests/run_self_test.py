"""
自测脚本：用注入漏洞的 fixture 验证审计 Agent 的检测能力。

用法:
    python -m tests.run_self_test                    # 完整测试（含LLM）
    python -m tests.run_self_test --static-only      # 仅静态分析
    python -m tests.run_self_test --verbose           # 详细输出
"""

import argparse
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from tests.test_fixtures import generate_fixtures, FIXTURES
from audit_engine.static_analyzer import analyze_repo, analyze_file
from audit_engine.report_generator import generate_report, save_report


def run_static_test(verbose: bool = False) -> dict:
    """仅运行静态分析器测试"""
    
    # 1. 生成 fixtures
    fixtures_dir = os.path.join(PROJECT_ROOT, "test_fixtures")
    generate_fixtures(fixtures_dir)
    
    print("\n" + "=" * 60)
    print("STATIC ANALYSIS SELF-TEST")
    print("=" * 60)
    
    results = {}
    
    for fixture_name, fixture_data in FIXTURES.items():
        fixture_path = os.path.join(fixtures_dir, fixture_name)
        category = fixture_data["category"]
        expected_severity = fixture_data["severity"]
        
        # 运行静态分析
        static_results, scan_stats = analyze_repo(fixture_path)
        
        # 汇总结果
        all_findings = []
        all_dep_issues = []
        max_severity = "SAFE"
        obfuscation_detected = False
        
        severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "SAFE": 0}
        
        for sr in static_results:
            if hasattr(sr, "findings"):
                for f in sr.findings:
                    sev = f.severity if hasattr(f, "severity") else "LOW"
                    all_findings.append({
                        "file": sr.file,
                        "line": f.line if hasattr(f, "line") else 0,
                        "severity": sev,
                        "title": f.title if hasattr(f, "title") else "",
                        "category": f.category if hasattr(f, "category") else "",
                    })
                    if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                        max_severity = sev
                        
            if hasattr(sr, "obfuscation_score") and sr.obfuscation_score > 0.5:
                obfuscation_detected = True
                if severity_order.get("HIGH", 0) > severity_order.get(max_severity, 0):
                    max_severity = "HIGH"
                    
            if hasattr(sr, "dependency_issues"):
                for di in sr.dependency_issues:
                    all_dep_issues.append(di)
                    sev = di.get("severity", "LOW")
                    if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                        max_severity = sev
        
        # 评判
        if category == "TRUE_POSITIVE":
            passed = max_severity in ("CRITICAL", "HIGH") or obfuscation_detected
        elif category == "TRUE_NEGATIVE":
            # 静态分析允许 MEDIUM（LLM 层会根据上下文降级）
            # 但 HIGH/CRITICAL 是不可接受的误报
            passed = max_severity in ("SAFE", "LOW", "INFO", "MEDIUM")
        elif category == "GRAY_AREA":
            # 灰色地带应该有发现但不一定是 CRITICAL
            passed = len(all_findings) > 0
        else:
            passed = True
            
        status = "✅ PASS" if passed else "❌ FAIL"
        
        results[fixture_name] = {
            "category": category,
            "expected_severity": expected_severity,
            "detected_severity": max_severity,
            "findings_count": len(all_findings),
            "dep_issues_count": len(all_dep_issues),
            "obfuscation_detected": obfuscation_detected,
            "passed": passed,
        }
        
        print(f"\n  {status} [{category}] {fixture_name}")
        print(f"         Expected: {expected_severity} | Detected: {max_severity}")
        print(f"         Findings: {len(all_findings)} code, {len(all_dep_issues)} deps")
        
        if verbose:
            for f in all_findings:
                print(f"           - [{f['severity']}] {f['title']} ({f['file']}:{f['line']})")
            for d in all_dep_issues:
                print(f"           - [{d.get('severity')}] {d.get('description')}")
        
        if not passed:
            if category == "TRUE_POSITIVE":
                print(f"         ⚠️  MISSED: Expected detection of {expected_severity} threat")
                if "expected_findings" in fixture_data:
                    for ef in fixture_data["expected_findings"]:
                        print(f"            Expected: [{ef['severity']}] {ef['type']} near '{ef['line_hint']}'")
            elif category == "TRUE_NEGATIVE":
                print(f"         ⚠️  FALSE ALARM: Flagged as {max_severity} but should be SAFE")
    
    # 汇总
    total = len(results)
    passed = sum(1 for r in results.values() if r["passed"])
    
    tp_total = sum(1 for r in results.values() if r["category"] == "TRUE_POSITIVE")
    tp_pass = sum(1 for r in results.values() if r["category"] == "TRUE_POSITIVE" and r["passed"])
    tn_total = sum(1 for r in results.values() if r["category"] == "TRUE_NEGATIVE")
    tn_pass = sum(1 for r in results.values() if r["category"] == "TRUE_NEGATIVE" and r["passed"])
    ga_total = sum(1 for r in results.values() if r["category"] == "GRAY_AREA")
    ga_pass = sum(1 for r in results.values() if r["category"] == "GRAY_AREA" and r["passed"])
    
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed}/{total} tests passed")
    print(f"  Detection Rate (malicious):    {tp_pass}/{tp_total} = {tp_pass/tp_total:.0%}" if tp_total else "  Detection Rate: N/A")
    print(f"  False Positive Rate (safe):    {tn_total - tn_pass}/{tn_total} = {(tn_total - tn_pass)/tn_total:.0%}" if tn_total else "  FP Rate: N/A")
    print(f"  Gray Area Detection:           {ga_pass}/{ga_total} = {ga_pass/ga_total:.0%}" if ga_total else "  Gray Area: N/A")
    print(f"{'='*60}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Self-test for Skill Audit Agent")
    parser.add_argument("--static-only", action="store_true", help="Only test static analyzer")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    results = run_static_test(verbose=args.verbose)
    
    # 保存结果
    results_path = os.path.join(PROJECT_ROOT, "self_test_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {results_path}")


if __name__ == "__main__":
    main()
