"""
Phase 5: 审计报告生成器
- 生成结构化 Markdown 报告
- 生成 JSON 元数据
- 按 skill/commit/version 组织目录结构
"""

import json
import os
import subprocess
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field


@dataclass
class AuditMeta:
    """审计元数据"""
    skill_owner: str
    skill_repo: str
    skill_url: str
    commit_hash: str
    commit_date: str
    audit_agent_version: str
    audit_date: str
    total_files_scanned: int
    total_files_in_repo: int
    total_findings: int
    severity_counts: dict
    overall_risk: str
    overall_confidence: float
    scan_stats: dict = field(default_factory=dict)
    llm_failures: int = 0
    is_incomplete: bool = False


def get_repo_commit_info(repo_path: str) -> dict:
    """获取 git 仓库的 commit 信息"""
    info = {"commit_hash": "unknown", "commit_date": "unknown"}
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%H|%aI"],
            cwd=repo_path, capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split("|")
            info["commit_hash"] = parts[0]
            info["commit_date"] = parts[1] if len(parts) > 1 else "unknown"
    except Exception:
        pass
    return info


def generate_report(
    skill_owner: str,
    skill_repo: str,
    skill_url: str,
    commit_info: dict,
    audit_version: str,
    static_results: list,
    llm_results: list,
    scenario_results: list = None,
    scan_stats: dict = None,
    trust_chain_result: dict = None,
) -> tuple[str, dict]:
    """
    生成完整的审计报告。
    返回 (markdown_content, meta_dict)
    """
    now = datetime.now(timezone.utc).isoformat()
    scan_stats = scan_stats or {}

    # 判断审计是否真正执行了
    files_analyzed = scan_stats.get("files_analyzed", len(static_results))
    total_files = scan_stats.get("total_files_walked", 0)
    dominant_lang = scan_stats.get("dominant_language", "")
    dominant_supported = scan_stats.get("dominant_language_supported", True)
    code_coverage = scan_stats.get("code_coverage_ratio", 1.0)
    is_low_coverage = scan_stats.get("is_low_coverage", False)
    unsupported_code = scan_stats.get("unsupported_code_counts", {})

    is_incomplete = (files_analyzed == 0 and total_files > 0)
    is_partial = (not dominant_supported) or is_low_coverage  # 扫了一部分但核心没覆盖
    is_empty_repo = (total_files == 0)

    # 统计严重程度
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "SAFE": 0}

    all_findings = []

    # 处理静态分析结果
    for sr in static_results:
        if hasattr(sr, 'findings'):
            for f in sr.findings:
                sev = f.severity if hasattr(f, 'severity') else f.get("severity", "LOW")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                all_findings.append({
                    "source": "static",
                    "file": sr.file if hasattr(sr, 'file') else f.get("file", "unknown"),
                    "severity": sev,
                    "title": f.title if hasattr(f, 'title') else f.get("title", ""),
                    "description": f.description if hasattr(f, 'description') else f.get("description", ""),
                    "code_context": f.code_context if hasattr(f, 'code_context') else f.get("code_context", ""),
                    "line": f.line if hasattr(f, 'line') else f.get("line", 0),
                    "is_user_input_tainted": getattr(f, 'is_user_input_tainted', False),
                })
        if hasattr(sr, 'dependency_issues'):
            for di in sr.dependency_issues:
                sev = di.get("severity", "HIGH")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                all_findings.append({
                    "source": "dependency",
                    "file": sr.file,
                    "severity": sev,
                    "title": f"Dependency issue: {di.get('package', 'unknown')}",
                    "description": di.get("description", ""),
                    "code_context": "",
                    "line": 0,
                })

    # 处理 LLM 审查结果
    llm_failures = 0
    for lr in llm_results:
        if hasattr(lr, 'final_severity'):
            sev = lr.final_severity
        elif isinstance(lr, dict):
            sev = lr.get("final_severity", "UNKNOWN")
        else:
            continue
        if sev == "UNKNOWN":
            llm_failures += 1
        else:
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total_findings = sum(v for k, v in severity_counts.items() if k not in ("SAFE", "INFO"))

    # 确定总体风险 —— 区分完全无法审计 / 部分覆盖 / 正常审计
    if is_incomplete:
        overall_risk = "INCOMPLETE"
    elif is_empty_repo:
        overall_risk = "EMPTY_REPO"
    else:
        # 先按 finding 确定 severity
        if severity_counts.get("CRITICAL", 0) > 0:
            base_risk = "CRITICAL"
        elif severity_counts.get("HIGH", 0) > 0:
            base_risk = "HIGH"
        elif severity_counts.get("MEDIUM", 0) > 0:
            base_risk = "MEDIUM"
        elif severity_counts.get("LOW", 0) > 0:
            base_risk = "LOW"
        elif files_analyzed > 0:
            base_risk = "SAFE"
        else:
            base_risk = "UNKNOWN"

        # 如果核心代码未被覆盖，追加 PARTIAL 标记
        if is_partial:
            if total_findings > 0:
                overall_risk = f"{base_risk} (PARTIAL AUDIT — {dominant_lang} code not analyzed)"
            else:
                overall_risk = f"PARTIAL — core language ({dominant_lang}) not analyzed"
        else:
            overall_risk = base_risk

    # 置信度 —— 根据覆盖率调整
    confidences = []
    for lr in llm_results:
        if hasattr(lr, 'final_confidence'):
            if lr.final_severity != "UNKNOWN":
                confidences.append(lr.final_confidence)
        elif isinstance(lr, dict) and lr.get("final_severity") != "UNKNOWN":
            confidences.append(lr.get("final_confidence", 0.5))

    if confidences:
        overall_confidence = sum(confidences) / len(confidences)
    elif files_analyzed > 0 and total_findings >= 0:
        overall_confidence = 0.7
    elif is_incomplete:
        overall_confidence = 0.0
    else:
        overall_confidence = 0.0

    # 覆盖率惩罚：覆盖率低时降低置信度
    if is_partial and overall_confidence > 0:
        overall_confidence = overall_confidence * code_coverage
        overall_confidence = max(overall_confidence, 0.05)  # 至少显示 5%，不显示 0% 以区分完全失败

    # ========== 预处理：信任假设降级后重新统计 severity_counts ==========
    # llm_results 的 final_severity 在 apply_downgrade 里已经被修改过
    # 这里重新统计 LLM 部分，确保 overall_risk 反映降级后的真实状态
    if trust_chain_result:
        # 重置 LLM 贡献的计数（static findings 不受信任假设影响）
        llm_sev_keys = {lr.get("final_severity") for lr in llm_results
                        if isinstance(lr, dict) and lr.get("final_severity") not in (None, "UNKNOWN")}
        # 只重算 LLM 部分
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"]:
            severity_counts[sev] = 0
        for sr in static_results:
            if hasattr(sr, 'findings'):
                for f in sr.findings:
                    sev = f.severity if hasattr(f, 'severity') else f.get("severity", "LOW")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
            if hasattr(sr, 'dependency_issues'):
                for di in sr.dependency_issues:
                    sev = di.get("severity", "HIGH")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for lr in llm_results:
            sev = lr.get("final_severity") if isinstance(lr, dict) else getattr(lr, "final_severity", None)
            if sev and sev != "UNKNOWN":
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # 重新计算 overall_risk
        total_findings = sum(v for k, v in severity_counts.items() if k not in ("SAFE", "INFO"))
        if not is_incomplete and not is_empty_repo:
            if severity_counts.get("CRITICAL", 0) > 0:
                base_risk = "CRITICAL"
            elif severity_counts.get("HIGH", 0) > 0:
                base_risk = "HIGH"
            elif severity_counts.get("MEDIUM", 0) > 0:
                base_risk = "MEDIUM"
            elif severity_counts.get("LOW", 0) > 0:
                base_risk = "LOW"
            elif files_analyzed > 0:
                base_risk = "SAFE"
            else:
                base_risk = "UNKNOWN"
            if is_partial:
                if total_findings > 0:
                    overall_risk = f"{base_risk} (PARTIAL AUDIT — {dominant_lang} code not analyzed)"
                else:
                    overall_risk = f"PARTIAL — core language ({dominant_lang}) not analyzed"
            else:
                overall_risk = base_risk

    # ========== 生成 Markdown ==========
    md_lines = []
    md_lines.append(f"# Security Audit Report: {skill_owner}/{skill_repo}")
    md_lines.append("")

    # ---- 警告横幅 ----
    if is_incomplete:
        md_lines.append("> ⛔ **AUDIT INCOMPLETE** — No source files (.py/.js/.ts) were found or analyzed.")
        md_lines.append(f"> The repository contains {total_files} files, but none match supported languages.")
        md_lines.append("> This does NOT mean the code is safe. Manual review is required.")
        md_lines.append("")
    elif is_empty_repo:
        md_lines.append("> ℹ️ **NOT AN AI SKILL REPOSITORY** — No files were found matching AI skill patterns.")
        md_lines.append("> This scanner targets AI agent skill repos with `.py`, `.js`, `.ts`, `.yaml`, or prompt `.md` files.")
        md_lines.append("> This repository does not appear to contain auditable AI skill code.")
        md_lines.append("")
    elif is_partial and not dominant_supported:
        unsup_str = ", ".join(f"{lang} ({n} files)" for lang, n in sorted(unsupported_code.items(), key=lambda x: -x[1]))
        md_lines.append(f"> ⚠️ **CORE LANGUAGE NOT SUPPORTED** — This repo's dominant language is **{dominant_lang}**, which is not currently analyzed.")
        md_lines.append(f"> Unsupported code: {unsup_str}")
        md_lines.append(f"> Only {files_analyzed} peripheral files (scripts, configs) were scanned. The core business logic was **NOT audited**.")
        md_lines.append(f"> This result does **NOT** represent the security posture of the project. Manual review required.")
        md_lines.append("")
    elif is_partial and is_low_coverage:
        md_lines.append(f"> ⚠️ **LOW CODE COVERAGE** — Only {code_coverage:.0%} of source code files were analyzed.")
        if unsupported_code:
            unsup_str = ", ".join(f"{lang} ({n})" for lang, n in sorted(unsupported_code.items(), key=lambda x: -x[1]))
            md_lines.append(f"> Unsupported languages skipped: {unsup_str}")
        md_lines.append(f"> Findings below only reflect the analyzed subset. Unanalyzed code may contain additional issues.")
        md_lines.append("")
    elif llm_failures > 0:
        md_lines.append(f"> ⚠️ **LLM REVIEW PARTIALLY FAILED** — {llm_failures}/{len(llm_results)} LLM calls returned errors.")
        md_lines.append("> Check that OPENROUTER_API_KEY is set correctly.")
        md_lines.append("")
    elif not llm_results and total_findings > 0:
        md_lines.append("> ℹ️ **Static analysis only** — LLM cross-validation was not performed.")
        md_lines.append("> Run without `--no-llm` for deeper analysis.")
        md_lines.append("")

    # ---- 基本信息表 ----
    md_lines.append(f"| Field | Value |")
    md_lines.append(f"|-------|-------|")
    md_lines.append(f"| Repository | [{skill_owner}/{skill_repo}]({skill_url}) |")
    md_lines.append(f"| Commit | `{commit_info.get('commit_hash', 'unknown')[:12]}` |")
    md_lines.append(f"| Commit Date | {commit_info.get('commit_date', 'unknown')} |")
    md_lines.append(f"| Audit Agent | {audit_version} |")
    md_lines.append(f"| Audit Date | {now} |")
    md_lines.append(f"| Overall Risk | **{overall_risk}** |")
    md_lines.append(f"| Confidence | {overall_confidence:.0%} |")
    md_lines.append(f"| Files Scanned | {files_analyzed} / {total_files} |")
    md_lines.append("")

    # ========== 安全条件摘要（置顶，核心新增） ==========
    if trust_chain_result:
        assumption_results = trust_chain_result.get("trust_assumption_results", [])
        raw_assumptions   = trust_chain_result.get("trust_assumptions", [])
        all_assumptions   = assumption_results if assumption_results else raw_assumptions

        verified_list    = [a for a in all_assumptions if a.get("verified") is True]
        unverified_list  = [a for a in all_assumptions if a.get("verified") is not True]
        any_downgraded   = any(a.get("downgrade_applied") for a in verified_list)

        if all_assumptions:
            md_lines.append("## 🔐 Trust Analysis")
            md_lines.append("")

            # ---- 安全条件清单（核心，置顶） ----
            md_lines.append("### This skill is safe to use when the following conditions are met:")
            md_lines.append("")
            idx = 1
            for a in all_assumptions:
                subj = a.get("subject", "")
                claim = a.get("claim", "")
                v = a.get("verified")
                conf = a.get("verification_confidence", 0)
                if v is True:
                    check = "✅"
                elif v is False:
                    check = "❌"
                else:
                    check = "⚠️"
                md_lines.append(f"{idx}. {check} **{subj}** is trustworthy *(confidence: {conf:.0%})*")
                idx += 1
            md_lines.append("")

            # ---- 逐条展开验证结果 ----
            if verified_list:
                md_lines.append("---")
                md_lines.append("")
                md_lines.append("### ✅ Verified — Conditions Confirmed")
                md_lines.append("")
                for a in verified_list:
                    subj     = a.get("subject", "")
                    claim    = a.get("claim", "")
                    conf     = a.get("verification_confidence", 0)
                    summary  = a.get("verification_summary", "")
                    evidence = a.get("verification_evidence", [])
                    downgraded = a.get("downgrade_applied", False)

                    md_lines.append(f"#### ✅ {subj} &nbsp; `{conf:.0%} confidence`")
                    md_lines.append("")
                    md_lines.append(f"> **Trust assumption:** {claim}")
                    md_lines.append("")
                    if summary:
                        md_lines.append(f"{summary}")
                        md_lines.append("")
                    for ev in evidence[:3]:
                        icon = "🟢" if ev.get("weight") in ("strong", "positive") else "🟡"
                        title = ev.get("title", "")
                        url   = ev.get("url", "")
                        snip  = ev.get("snippet", "")[:180]
                        if url:
                            md_lines.append(f"- {icon} [{title}]({url})")
                        else:
                            md_lines.append(f"- {icon} {title}")
                        if snip:
                            md_lines.append(f"  *{snip}*")
                    if evidence:
                        md_lines.append("")
                    if downgraded:
                        md_lines.append(
                            "**🔽 Risk level adjusted:** Related findings have been downgraded "
                            "because this assumption is verified — they are no longer counted as CRITICAL."
                        )
                        md_lines.append("")

            # ---- 未能验证的假设 ----
            if unverified_list:
                md_lines.append("---")
                md_lines.append("")
                md_lines.append("### ⚠️ Unverified — Manual Review Required")
                md_lines.append("")
                md_lines.append(
                    "> These assumptions **could not be automatically verified**. "
                    "Please confirm them manually before using this skill in production."
                )
                md_lines.append("")
                for a in unverified_list:
                    subj        = a.get("subject", "")
                    claim       = a.get("claim", "")
                    why         = a.get("why_it_matters", "")
                    consequence = a.get("consequence_if_false", "")
                    v           = a.get("verified")
                    conf        = a.get("verification_confidence", 0)
                    summary     = a.get("verification_summary", "")

                    icon  = "❌" if v is False else "❓"
                    label = f"Verification FAILED ({conf:.0%})" if v is False else f"Inconclusive ({conf:.0%})"
                    md_lines.append(f"#### {icon} {subj} &nbsp; `{label}`")
                    md_lines.append("")
                    md_lines.append(f"> **Trust assumption:** {claim}")
                    md_lines.append("")
                    if why:
                        md_lines.append(f"**Why it matters:** {why}")
                        md_lines.append("")
                    if consequence:
                        md_lines.append(f"**If false:** ⚠️ {consequence}")
                        md_lines.append("")
                    if summary:
                        md_lines.append(f"*Verification result: {summary}*")
                        md_lines.append("")

            md_lines.append("---")
            md_lines.append("")

    # ---- 扫描摘要 ----
    md_lines.append("## Scan Summary")
    md_lines.append("")
    md_lines.append(f"| Metric | Value |")
    md_lines.append(f"|--------|-------|")
    md_lines.append(f"| Total files in repo | {total_files} |")
    md_lines.append(f"| Files analyzed | {files_analyzed} |")
    md_lines.append(f"| Skipped (unsupported type) | {scan_stats.get('files_skipped_type', 'N/A')} |")
    md_lines.append(f"| Skipped (too large) | {scan_stats.get('files_skipped_size', 'N/A')} |")

    if scan_stats.get("analyzed_type_counts"):
        breakdown = ", ".join(f"{lang}: {n}" for lang, n in scan_stats["analyzed_type_counts"].items())
        md_lines.append(f"| Analyzed by language | {breakdown} |")
    if dominant_lang and dominant_lang != "N/A":
        supported_tag = "✅ supported" if dominant_supported else "❌ NOT SUPPORTED"
        md_lines.append(f"| Dominant language | {dominant_lang} ({supported_tag}) |")
    if scan_stats.get("code_files_total", 0) > 0:
        md_lines.append(f"| Code coverage | {scan_stats.get('code_files_analyzed', 0)}/{scan_stats['code_files_total']} code files ({code_coverage:.0%}) |")
    if unsupported_code:
        unsup_str = ", ".join(f"{lang}({n})" for lang, n in sorted(unsupported_code.items(), key=lambda x: -x[1]))
        md_lines.append(f"| Unsupported code | {unsup_str} |")
    if scan_stats.get("file_type_counts"):
        top_types = sorted(scan_stats["file_type_counts"].items(), key=lambda x: -x[1])[:8]
        type_str = ", ".join(f"{ext}({n})" for ext, n in top_types)
        md_lines.append(f"| Top file types | {type_str} |")
    md_lines.append("")

    # ---- 严重程度摘要 ----
    md_lines.append("## Severity Summary")
    md_lines.append("")
    md_lines.append("| Severity | Count |")
    md_lines.append("|----------|-------|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"]:
        count = severity_counts.get(sev, 0)
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪", "SAFE": "🟢"}.get(sev, "")
        md_lines.append(f"| {emoji} {sev} | {count} |")
    md_lines.append("")

    # 详细发现
    md_lines.append("## Detailed Findings")
    md_lines.append("")

    # 按严重程度排序
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "SAFE": 5}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

    for i, finding in enumerate(all_findings, 1):
        sev = finding["severity"]
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
        md_lines.append(f"### {emoji} Finding #{i}: {finding['title']}")
        md_lines.append("")
        md_lines.append(f"- **File**: `{finding['file']}`")
        md_lines.append(f"- **Line**: {finding['line']}")
        md_lines.append(f"- **Severity**: {sev}")
        md_lines.append(f"- **Source**: {finding['source']}")
        if finding.get("is_user_input_tainted"):
            md_lines.append(f"- **⚠️ User input flows into this call**")
        md_lines.append(f"- **Description**: {finding['description']}")
        md_lines.append("")
        if finding["code_context"]:
            md_lines.append("```")
            md_lines.append(finding["code_context"])
            md_lines.append("```")
            md_lines.append("")

    # LLM 共识分析
    md_lines.append("## LLM Cross-Validation Results")
    md_lines.append("")

    for j, lr in enumerate(llm_results):
        lr_dict = lr if isinstance(lr, dict) else (lr.to_dict() if hasattr(lr, 'to_dict') else {})
        md_lines.append(f"### Analysis Group #{j + 1}")
        md_lines.append("")
        md_lines.append(f"- **Final Severity**: {lr_dict.get('final_severity', 'N/A')}")
        md_lines.append(f"- **Confidence**: {lr_dict.get('final_confidence', 0):.0%}")
        md_lines.append(f"- **Is Malicious**: {lr_dict.get('is_malicious', False)}")
        md_lines.append(f"- **Is Gray Area**: {lr_dict.get('is_gray_area', False)}")
        md_lines.append("")

        # 灰色地带详细分析
        gray_analysis = lr_dict.get("gray_area_analysis")
        if gray_analysis:
            md_lines.append("#### Gray Area Analysis")
            md_lines.append("")
            md_lines.append(gray_analysis)
            md_lines.append("")

        # 各模型意见
        for verdict in lr_dict.get("individual_verdicts", []):
            md_lines.append(f"**{verdict.get('role', 'unknown')}** ({verdict.get('model', 'N/A')}):")
            md_lines.append(f"> {verdict.get('summary', 'N/A')}")
            md_lines.append("")

        # 分歧记录
        disagreements = lr_dict.get("disagreements", [])
        if disagreements:
            md_lines.append("#### Disagreements Between Models")
            md_lines.append("")
            for d in disagreements:
                md_lines.append(f"- **{d['role']}**: {d['severity']} - {d['summary']}")
            md_lines.append("")

    # 场景模拟
    if scenario_results:
        md_lines.append("## Scenario Simulation Results")
        md_lines.append("")
        for k, sr in enumerate(scenario_results):
            if isinstance(sr, dict) and "scenarios" in sr:
                for scenario in sr["scenarios"]:
                    risk = scenario.get("risk_level", "UNKNOWN")
                    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "NONE": "🟢"}.get(risk, "⚪")
                    md_lines.append(f"### {emoji} {scenario.get('name', 'Unknown Scenario')}")
                    md_lines.append(f"- **Risk Level**: {risk}")
                    md_lines.append(f"- **Safe**: {scenario.get('is_safe', 'Unknown')}")
                    md_lines.append(f"- **Description**: {scenario.get('description', 'N/A')}")
                    md_lines.append("")

    # ========== 信任链分析 ==========
    if trust_chain_result and (trust_chain_result.get("verify_facts") or trust_chain_result.get("data_flows")):
        verdict = trust_chain_result.get("overall_trust_verdict", "VERIFY_BEFORE_USE")
        verdict_emoji = {"TRUSTED": "✅", "VERIFY_BEFORE_USE": "⚠️", "DO_NOT_USE": "🚫"}.get(verdict, "⚠️")

        md_lines.append("## Trust Chain Analysis")
        md_lines.append("")
        md_lines.append(f"**Overall Trust Verdict**: {verdict_emoji} **{verdict}**")
        md_lines.append(f"*{trust_chain_result.get('verdict_reason', '')}*")
        md_lines.append("")
        md_lines.append(trust_chain_result.get("trust_chain_summary", ""))
        md_lines.append("")
        md_lines.append("*(Trust assumptions and verification details are shown at the top of this report.)*")
        md_lines.append("")

        # ── 数据流溯源 ──────────────────────────────────────────────
        data_flows = trust_chain_result.get("data_flows", [])
        if data_flows:
            md_lines.append("### Data Flow Sources")
            md_lines.append("")
            md_lines.append("| Category | Description | Source | Required Trust | Risk |")
            md_lines.append("|----------|-------------|--------|----------------|------|")
            for df in data_flows:
                risk = df.get("risk_level", "UNKNOWN")
                risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk, "⚪")
                source = df.get("source", "unknown")
                desc = df.get("description", "")
                detail = df.get("source_detail", "")
                # 关联的信任假设
                req_trust = df.get("required_trust_assumptions", [])
                trust_ref = ", ".join(req_trust) if req_trust else "—"
                md_lines.append(
                    f"| {df.get('category', '')} | {desc} | `{source}` — {detail} | {trust_ref} | {risk_emoji} {risk} |"
                )
            md_lines.append("")

        # ── 3. 需要人工核验的 Facts ────────────────────────────────────
        verify_facts = trust_chain_result.get("verify_facts", [])
        if verify_facts:
            md_lines.append("### Manual Verification Checklist")
            md_lines.append("")
            md_lines.append("> Items that cannot be auto-verified — check these before deploying this skill.")
            md_lines.append("")

            priority_order = {"MUST": 0, "SHOULD": 1, "NICE_TO_HAVE": 2}
            sorted_facts = sorted(verify_facts, key=lambda f: priority_order.get(f.get("priority", "SHOULD"), 1))

            for i, fact in enumerate(sorted_facts, 1):
                priority = fact.get("priority", "SHOULD")
                priority_badge = {"MUST": "🔴 MUST", "SHOULD": "🟡 SHOULD", "NICE_TO_HAVE": "🔵 NICE TO HAVE"}.get(priority, priority)
                md_lines.append(f"#### {i}. [{priority_badge}] {fact.get('fact', '')}")
                md_lines.append("")
                how = fact.get("how_to_verify", "")
                if how:
                    md_lines.append(f"**How to verify:** {how}")
                    md_lines.append("")
                impact = fact.get("what_happens_if_wrong", "")
                if impact:
                    md_lines.append(f"**If wrong:** ⚠️ {impact}")
                    md_lines.append("")

    # 结尾
    md_lines.append("---")
    md_lines.append(f"*Generated by Skill Audit Agent {audit_version} on {now}*")

    markdown = "\n".join(md_lines)

    # ========== 生成元数据 ==========
    meta = AuditMeta(
        skill_owner=skill_owner,
        skill_repo=skill_repo,
        skill_url=skill_url,
        commit_hash=commit_info.get("commit_hash", "unknown"),
        commit_date=commit_info.get("commit_date", "unknown"),
        audit_agent_version=audit_version,
        audit_date=now,
        total_files_scanned=files_analyzed,
        total_files_in_repo=total_files,
        total_findings=total_findings,
        severity_counts=severity_counts,
        overall_risk=overall_risk,
        overall_confidence=overall_confidence,
        scan_stats=scan_stats,
        llm_failures=llm_failures,
        is_incomplete=is_incomplete,
    )

    return markdown, asdict(meta)


def save_report(
    output_dir: str,
    skill_owner: str,
    skill_repo: str,
    commit_hash: str,
    audit_version: str,
    markdown: str,
    meta: dict,
):
    """按目录结构保存报告"""
    # 创建目录: output_dir/owner/repo/commit_hash[:12]/
    short_hash = commit_hash[:12] if commit_hash != "unknown" else "latest"
    report_dir = os.path.join(output_dir, skill_owner, skill_repo, short_hash)
    os.makedirs(report_dir, exist_ok=True)

    # 保存 markdown
    md_path = os.path.join(report_dir, f"{audit_version}_audit_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(markdown)

    # 保存 meta
    meta_path = os.path.join(report_dir, f"{audit_version}_audit_meta.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    return report_dir


def update_index(output_dir: str, meta: dict):
    """更新全局索引"""
    index_path = os.path.join(output_dir, "_index.json")
    index = []
    if os.path.exists(index_path):
        with open(index_path, "r") as f:
            try:
                index = json.load(f)
            except json.JSONDecodeError:
                index = []

    # 去重（同一 repo + commit + version 只保留最新）
    key = f"{meta['skill_owner']}/{meta['skill_repo']}/{meta['commit_hash'][:12]}/{meta['audit_agent_version']}"
    index = [item for item in index if item.get("key") != key]
    meta["key"] = key
    index.append(meta)

    with open(index_path, "w") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
