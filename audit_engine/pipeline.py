"""
主审计流水线：串联所有阶段
Phase 1: 静态分析
Phase 2: 上下文分析（README/SKILL.md 解析）
Phase 3: 多模型 LLM 审查
Phase 4: 场景模拟
Phase 5: 报告生成

用法:
    python -m audit_engine.pipeline --repo /path/to/cloned/repo --owner owner --name repo_name
    python -m audit_engine.pipeline --url https://github.com/owner/repo
    python -m audit_engine.pipeline --batch   # 批量审计 configs 中的所有目标
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# 确保项目根目录在 path 中
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from audit_engine.static_analyzer import analyze_repo, StaticAnalysisResult, ScanStats
from audit_engine.llm_reviewer import MultiModelReviewer, ConsensusResult, run_trust_chain_analysis, LLMClient
from audit_engine.trust_verifier import (
    extract_trust_assumptions, verify_trust_assumptions, apply_downgrade, TrustAssumption
)
from audit_engine.report_generator import (
    generate_report, save_report, update_index, get_repo_commit_info,
)
from configs.audit_config import AUDIT_AGENT_VERSION
from audit_engine.discovery import discover_skills, load_discovered_skills


# ============================================================
# Phase 2: 上下文分析 - 理解 Skill 的目的
# ============================================================

def extract_skill_context(repo_path: str) -> str:
    """
    从 README、SKILL.md、package.json 等文件中提取 skill 的描述和目的。
    这对于区分"bug vs feature"至关重要。
    """
    context_parts = []

    # 1. README
    for readme_name in ["README.md", "README.rst", "README.txt", "README"]:
        readme_path = os.path.join(repo_path, readme_name)
        if os.path.exists(readme_path):
            try:
                with open(readme_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    # 只取前 2000 字符，避免过长
                    context_parts.append(f"## README (first 2000 chars):\n{content[:2000]}")
            except Exception:
                pass
            break

    # 2. SKILL.md
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
        for f in files:
            if f.upper() == "SKILL.MD":
                try:
                    with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                        context_parts.append(f"## SKILL.MD:\n{content[:2000]}")
                except Exception:
                    pass
                break
        if len(context_parts) >= 2:
            break

    # 3. package.json description
    pkg_path = os.path.join(repo_path, "package.json")
    if os.path.exists(pkg_path):
        try:
            with open(pkg_path, "r") as f:
                pkg = json.load(f)
                desc = pkg.get("description", "")
                name = pkg.get("name", "")
                context_parts.append(f"## package.json:\nName: {name}\nDescription: {desc}")
        except Exception:
            pass

    # 4. setup.py / pyproject.toml description
    for setup_file in ["setup.py", "pyproject.toml", "setup.cfg"]:
        setup_path = os.path.join(repo_path, setup_file)
        if os.path.exists(setup_path):
            try:
                with open(setup_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    context_parts.append(f"## {setup_file} (first 1000 chars):\n{content[:1000]}")
            except Exception:
                pass
            break

    if not context_parts:
        return "No skill documentation found. Unknown purpose."

    return "\n\n".join(context_parts)


# ============================================================
# 克隆仓库
# ============================================================

def clone_repo(url: str, clone_dir: str) -> str:
    """浅克隆仓库，返回本地路径"""
    repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
    repo_path = os.path.join(clone_dir, repo_name)

    if os.path.exists(repo_path):
        print(f"  [skip] {repo_name} already cloned")
        return repo_path

    print(f"  [clone] {url} → {repo_path}")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, repo_path],
            check=True, capture_output=True, timeout=120,
        )
    except subprocess.CalledProcessError as e:
        print(f"  [error] Failed to clone {url}: {e.stderr.decode()[:200]}")
        return None
    except subprocess.TimeoutExpired:
        print(f"  [error] Clone timed out for {url}")
        return None

    return repo_path


# ============================================================
# 主审计流程
# ============================================================

def audit_single_repo(
    repo_path: str,
    skill_owner: str,
    skill_repo: str,
    skill_url: str,
    output_dir: str,
    use_llm: bool = True,
    use_scenarios: bool = True,
) -> dict:
    """
    对单个仓库执行完整审计流程。
    """
    print(f"\n{'='*60}")
    print(f"Auditing: {skill_owner}/{skill_repo}")
    print(f"{'='*60}")

    start_time = time.time()

    # Phase 0: 获取 commit 信息
    print("  [Phase 0] Getting commit info...")
    commit_info = get_repo_commit_info(repo_path)
    print(f"  Commit: {commit_info['commit_hash'][:12]}")

    # Phase 0.5: 预检查 LLM API key
    if use_llm:
        api_key = os.environ.get("OPENROUTER_API_KEY", "")
        if not api_key:
            print("  ⚠️  WARNING: OPENROUTER_API_KEY not set!")
            print("     LLM cross-validation will be SKIPPED.")
            print("     Set it with: export OPENROUTER_API_KEY='sk-or-v1-...'")
            print("     Or use --no-llm to run static analysis only.")
            use_llm = False

    # Phase 1: 静态分析
    print("  [Phase 1] Running static analysis...")
    static_results, scan_stats = analyze_repo(repo_path)

    # 打印详细扫描诊断
    print(f"  ── Scan Summary ──")
    print(f"     Total files found:       {scan_stats.total_files_walked}")
    print(f"     Files analyzed:           {scan_stats.files_analyzed}")
    print(f"     Skipped (unsupported):    {scan_stats.files_skipped_type}")
    print(f"     Skipped (too large):      {scan_stats.files_skipped_size}")
    if scan_stats.files_skipped_error:
        print(f"     Skipped (read error):     {scan_stats.files_skipped_error}")

    if scan_stats.analyzed_type_counts:
        breakdown = ", ".join(f"{lang}: {n}" for lang, n in sorted(scan_stats.analyzed_type_counts.items()))
        print(f"     Analyzed by language:     {breakdown}")

    # 主语言 & 覆盖度诊断
    if scan_stats.dominant_language and scan_stats.dominant_language != "N/A":
        supported_tag = "✅ supported" if scan_stats.dominant_language_supported else "❌ NOT SUPPORTED"
        print(f"     Dominant language:        {scan_stats.dominant_language} ({supported_tag})")
    if scan_stats.code_files_total > 0:
        print(f"     Code coverage:            {scan_stats.code_files_analyzed}/{scan_stats.code_files_total} code files ({scan_stats.code_coverage_ratio:.0%})")

    # Prompt-based skill 检测
    if scan_stats.is_prompt_based:
        print(f"     📝 PROMPT-BASED SKILL detected: {scan_stats.skill_prompts_analyzed} skill prompt files analyzed")
        print(f"        (Core logic is in natural language .md files, not traditional code)")

    # 情况 1：完全没有分析到任何文件
    if scan_stats.files_analyzed == 0 and scan_stats.total_files_walked > 0:
        top_types = sorted(scan_stats.file_type_counts.items(), key=lambda x: -x[1])[:5]
        type_str = ", ".join(f"{ext}({n})" for ext, n in top_types)
        print(f"  ❌ NO FILES ANALYZED! Repo has {scan_stats.total_files_walked} files but none are supported")
        print(f"     Top file types: {type_str}")
        print(f"     This audit result will be marked as INCOMPLETE.")

    # 情况 2：主语言不被支持（核心代码漏扫）
    elif not scan_stats.dominant_language_supported:
        unsup_str = ", ".join(f"{lang}({n})" for lang, n in sorted(scan_stats.unsupported_code_counts.items(), key=lambda x: -x[1]))
        print(f"  ⚠️  DOMINANT LANGUAGE NOT SUPPORTED: {scan_stats.dominant_language}")
        print(f"     Unsupported code files: {unsup_str}")
        print(f"     Only peripheral files (scripts, configs) were analyzed.")
        print(f"     The core business logic was NOT audited. Result will be marked INCOMPLETE.")

    # 情况 3：覆盖率过低（虽然主语言被支持，但大量文件被跳过）
    elif scan_stats.is_low_coverage:
        print(f"  ⚠️  LOW CODE COVERAGE: Only {scan_stats.code_coverage_ratio:.0%} of code files were analyzed")
        if scan_stats.unsupported_code_counts:
            unsup_str = ", ".join(f"{lang}({n})" for lang, n in sorted(scan_stats.unsupported_code_counts.items(), key=lambda x: -x[1]))
            print(f"     Unsupported languages skipped: {unsup_str}")

    total_static_findings = sum(len(r.findings) for r in static_results if hasattr(r, 'findings'))
    total_dep_issues = sum(len(r.dependency_issues) for r in static_results if hasattr(r, 'dependency_issues'))
    print(f"  ── Findings: {total_static_findings} code, {total_dep_issues} dependency ──")

    # Phase 2: 上下文分析
    print("  [Phase 2] Extracting skill context...")
    skill_context = extract_skill_context(repo_path)
    print(f"  Context length: {len(skill_context)} chars")

    # 筛选需要 LLM 审查的发现（只审查有实际 finding 的文件）
    files_with_findings = [
        r for r in static_results
        if (hasattr(r, 'findings') and r.findings) or
           (hasattr(r, 'obfuscation_score') and r.obfuscation_score > 0.5) or
           (hasattr(r, 'dependency_issues') and r.dependency_issues) or
           (hasattr(r, 'language') and r.language in ("skill_prompt", "tool_config"))
    ]

    # 强制语义层审查：skill_prompt 文件即使静态发现为 0 也必须进入 LLM
    forced_skill_prompt_files = [
        r for r in static_results
        if hasattr(r, 'language') and r.language == "skill_prompt"
    ]
    existing_ids = {id(r) for r in files_with_findings}
    for r in forced_skill_prompt_files:
        if id(r) not in existing_ids:
            files_with_findings.append(r)
            existing_ids.add(id(r))

    llm_results = []
    scenario_results = []

    if use_llm and files_with_findings:
        print(f"  [Phase 3] LLM cross-validation on {len(files_with_findings)} files...")
        try:
            reviewer = MultiModelReviewer()

            for idx, sr in enumerate(files_with_findings[:10]):  # 限制最多审查 10 个文件
                print(f"    [{idx+1}/{min(len(files_with_findings),10)}] Reviewing {sr.file}...")
                # 准备数据
                findings_data = []
                code_contexts = []
                for f in (sr.findings if hasattr(sr, 'findings') else []):
                    fd = f.to_dict() if hasattr(f, 'to_dict') else f
                    findings_data.append(fd)
                    code_contexts.append(fd.get("code_context", ""))

                # 读取完整文件内容
                full_path = os.path.join(repo_path, sr.file)
                file_content = ""
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                        file_content = fh.read()[:8000]
                except Exception:
                    pass

                # 多模型审查
                consensus = reviewer.review_finding(
                    filepath=sr.file,
                    language=sr.language if hasattr(sr, 'language') else "unknown",
                    static_findings=findings_data,
                    code_context="\n---\n".join(code_contexts[:3]),
                    file_content=file_content,
                    skill_context=skill_context[:3000],
                )

                # 附加上下文标签：标记“无静态锚点但被语义层识别”的攻击场景
                cdict = consensus.to_dict() if hasattr(consensus, "to_dict") else dict(consensus)
                static_count = len(findings_data)
                forced_semantic_review = (getattr(sr, "language", "") == "skill_prompt" and static_count == 0)
                detected_semantic_attack = (
                    forced_semantic_review and (
                        cdict.get("is_malicious", False) or
                        cdict.get("final_severity") in ("CRITICAL", "HIGH", "MEDIUM")
                    )
                )
                cdict["_audit_file"] = sr.file
                cdict["_audit_language"] = getattr(sr, "language", "unknown")
                cdict["_static_finding_count"] = static_count
                cdict["_forced_semantic_review"] = forced_semantic_review
                cdict["_semantic_attack_detected"] = detected_semantic_attack
                llm_results.append(cdict)

                # 检查 LLM 是否真的返回了有效结果
                if consensus.final_severity == "UNKNOWN":
                    print(f"      ⚠️  LLM returned UNKNOWN — API call may have failed")

                # Phase 4: 场景模拟（仅对高风险文件）
                if use_scenarios:
                    max_sev = max(
                        (f.get("severity", "LOW") if isinstance(f, dict) else getattr(f, "severity", "LOW"))
                        for f in (sr.findings if hasattr(sr, 'findings') and sr.findings else [{"severity": "LOW"}])
                    )
                    if max_sev in ("CRITICAL", "HIGH"):
                        print(f"      [Phase 4] Scenario simulation...")
                        sim = reviewer.simulate_scenarios(
                            code_context="\n---\n".join(code_contexts[:3]),
                            file_content=file_content,
                            skill_context=skill_context[:3000],
                        )
                        scenario_results.append(sim)

        except Exception as e:
            print(f"  ❌ LLM review FAILED: {e}")
            import traceback
            traceback.print_exc()

    elif use_llm and not files_with_findings:
        if scan_stats.files_analyzed > 0:
            print("  [Phase 3] Static analysis found no issues — skipping LLM phase")
        else:
            print("  [Phase 3] No files were analyzed — nothing to send to LLM")
    else:
        print("  [Phase 3] LLM review disabled (--no-llm)")

    # Phase 3.5: 信任链分析（全局，包含所有文件）
    trust_chain_result = {}
    if use_llm:
        print("  [Phase 3.5] Trust chain analysis...")
        try:
            from configs.audit_config import LLM_CONFIGS
            tc_config = LLM_CONFIGS.get("security_analyst", list(LLM_CONFIGS.values())[0])
            tc_client = LLMClient(provider=tc_config.get("provider", "openrouter"))

            # 收集所有已分析文件的内容
            all_files_content = {}
            for sr in static_results[:8]:
                full_path = os.path.join(repo_path, sr.file)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                        all_files_content[sr.file] = fh.read()
                except Exception:
                    pass

            trust_chain_result = run_trust_chain_analysis(
                all_files_content=all_files_content,
                skill_context=skill_context[:3000],
                llm_client=tc_client,
                model=tc_config["model"],
            )
            verdict = trust_chain_result.get("overall_trust_verdict", "UNKNOWN")
            facts_count = len(trust_chain_result.get("verify_facts", []))
            print(f"  Trust verdict: {verdict} | {facts_count} facts to verify")

            # Phase 3.6: 自动验证信任假设
            assumptions = extract_trust_assumptions(trust_chain_result)
            if assumptions:
                print(f"  [Phase 3.6] Verifying {len(assumptions)} trust assumption(s) via web search...")
                def _progress(i, total, a):
                    print(f"    [{i+1}/{total}] Verifying: {a.subject} ({a.category})")
                assumptions = verify_trust_assumptions(assumptions, progress_callback=_progress)

                verified_count = sum(1 for a in assumptions if a.verified)
                failed_count = sum(1 for a in assumptions if a.verified is False)
                print(f"  Trust verification: {verified_count} passed, {failed_count} failed, "
                      f"{len(assumptions)-verified_count-failed_count} inconclusive")

                # 降级通过验证的假设关联的 findings
                llm_results, downgrade_log = apply_downgrade(llm_results, assumptions)
                if downgrade_log:
                    print(f"  Downgraded {len(downgrade_log)} finding(s):")
                    for entry in downgrade_log:
                        print(f"    {entry}")

                trust_chain_result["trust_assumption_results"] = [a.to_dict() for a in assumptions]
        except Exception as e:
            print(f"  ⚠️  Trust chain analysis failed: {e}")
            trust_chain_result = {}

    # Phase 5: 生成报告
    print("  [Phase 5] Generating report...")
    markdown, meta = generate_report(
        skill_owner=skill_owner,
        skill_repo=skill_repo,
        skill_url=skill_url,
        commit_info=commit_info,
        audit_version=AUDIT_AGENT_VERSION,
        static_results=static_results,
        llm_results=llm_results,
        scenario_results=scenario_results,
        scan_stats=scan_stats.to_dict() if hasattr(scan_stats, 'to_dict') else {},
        trust_chain_result=trust_chain_result,
    )

    report_dir = save_report(
        output_dir=output_dir,
        skill_owner=skill_owner,
        skill_repo=skill_repo,
        commit_hash=commit_info.get("commit_hash", "unknown"),
        audit_version=AUDIT_AGENT_VERSION,
        markdown=markdown,
        meta=meta,
    )

    update_index(output_dir, meta)

    elapsed = time.time() - start_time
    print(f"  [done] Report saved to {report_dir} ({elapsed:.1f}s)")
    print(f"  Overall risk: {meta['overall_risk']} (confidence: {meta['overall_confidence']:.0%})")

    return meta


# ============================================================
# 批量审计
# ============================================================

def audit_batch(
    output_dir: str,
    clone_dir: str,
    use_llm: bool = True,
    use_scenarios: bool = True,
    max_repos: int = None,
    refresh_discovery: bool = False,
):
    """
    批量审计：
    1. 从 VoltAgent awesome-list 索引仓库发现 skill
    2. 克隆每个 skill 仓库
    3. 逐个运行审计流水线
    """
    # Step 1: 发现 skill（有缓存机制）
    if not refresh_discovery:
        targets = load_discovered_skills(clone_dir)
    else:
        targets = None

    if not targets:
        targets = discover_skills(clone_dir, max_skills=max_repos or 0)

    if max_repos and len(targets) > max_repos:
        targets = targets[:max_repos]

    if not targets:
        print("No skills discovered. Check network and index repo URLs.")
        return []

    print(f"\nBatch audit: {len(targets)} skill repositories")
    print(f"Output: {output_dir}")
    print(f"Clone dir: {clone_dir}")
    print(f"LLM enabled: {use_llm}")
    print(f"Scenario simulation: {use_scenarios}")
    print()

    results_summary = []

    for target in targets:
        owner = target["owner"]
        repo = target["repo"]
        url = target["url"]

        # 克隆 skill 仓库
        repo_path = clone_repo(url, clone_dir)
        if not repo_path:
            results_summary.append({
                "owner": owner, "repo": repo,
                "status": "clone_failed",
            })
            continue

        # 审计
        try:
            meta = audit_single_repo(
                repo_path=repo_path,
                skill_owner=owner,
                skill_repo=repo,
                skill_url=url,
                output_dir=output_dir,
                use_llm=use_llm,
                use_scenarios=use_scenarios,
            )
            results_summary.append({
                "owner": owner, "repo": repo,
                "status": "completed",
                "risk": meta["overall_risk"],
                "findings": meta["total_findings"],
            })
        except Exception as e:
            print(f"  [error] Audit failed for {owner}/{repo}: {e}")
            results_summary.append({
                "owner": owner, "repo": repo,
                "status": "error",
                "error": str(e),
            })

    # 打印总结
    print("\n" + "=" * 60)
    print("BATCH AUDIT SUMMARY")
    print("=" * 60)
    for r in results_summary:
        status = r["status"]
        if status == "completed":
            print(f"  ✅ {r['owner']}/{r['repo']}: {r['risk']} ({r['findings']} findings)")
        elif status == "clone_failed":
            print(f"  ❌ {r['owner']}/{r['repo']}: Clone failed")
        else:
            print(f"  ⚠️  {r['owner']}/{r['repo']}: Error - {r.get('error', 'unknown')}")

    return results_summary


# ============================================================
# CLI 入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Skill Audit Agent - Security Auditor for AI Skills")

    # 运行模式（四选一）
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--repo", help="Audit a local repo at this path")
    mode.add_argument("--url", help="Clone a GitHub URL and audit it")
    mode.add_argument("--batch", action="store_true",
                       help="Discover skills from VoltAgent awesome-lists, then batch audit")
    mode.add_argument("--discover-only", action="store_true",
                       help="Only discover skills (don't audit), print the list")

    # 通用选项
    parser.add_argument("--owner", help="Repo owner (for report)", default="unknown")
    parser.add_argument("--name", help="Repo name (for report)", default="unknown")
    parser.add_argument("--output", default="./audit_results", help="Output directory for reports")
    parser.add_argument("--clone-dir", default="./cloned_repos", help="Directory for cloned repos")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM review (static only)")
    parser.add_argument("--no-scenarios", action="store_true", help="Disable scenario simulation")
    parser.add_argument("--max-repos", type=int, help="Max repos to audit in batch mode")
    parser.add_argument("--refresh", action="store_true",
                         help="Force re-discovery from index repos (ignore cache)")

    args = parser.parse_args()

    output_dir = os.path.abspath(args.output)
    clone_dir = os.path.abspath(args.clone_dir)
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(clone_dir, exist_ok=True)

    if args.discover_only:
        # 仅发现 skill，打印列表
        skills = discover_skills(clone_dir, max_skills=args.max_repos or 0)
        print(f"\nDiscovered {len(skills)} skills:")
        for i, s in enumerate(skills, 1):
            print(f"  {i:3d}. {s['owner']}/{s['repo']}")

    elif args.batch:
        audit_batch(
            output_dir=output_dir,
            clone_dir=clone_dir,
            use_llm=not args.no_llm,
            use_scenarios=not args.no_scenarios,
            max_repos=args.max_repos,
            refresh_discovery=args.refresh,
        )

    elif args.url:
        repo_path = clone_repo(args.url, clone_dir)
        if repo_path:
            owner = args.url.rstrip("/").split("/")[-2] if args.owner == "unknown" else args.owner
            name = args.url.rstrip("/").split("/")[-1].replace(".git", "") if args.name == "unknown" else args.name
            audit_single_repo(
                repo_path=repo_path,
                skill_owner=owner,
                skill_repo=name,
                skill_url=args.url,
                output_dir=output_dir,
                use_llm=not args.no_llm,
                use_scenarios=not args.no_scenarios,
            )

    elif args.repo:
        audit_single_repo(
            repo_path=os.path.abspath(args.repo),
            skill_owner=args.owner,
            skill_repo=args.name,
            skill_url=f"https://github.com/{args.owner}/{args.name}",
            output_dir=output_dir,
            use_llm=not args.no_llm,
            use_scenarios=not args.no_scenarios,
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
