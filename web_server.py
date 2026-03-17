"""
Skill Audit Web Server
Flask 后端：提供审计 API + 缓存 + SSE 进度流
"""

import json
import os
import re
import sys
import time
import threading
import queue
import subprocess
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template, Response, stream_with_context

# 确保项目根目录在 path 中
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from audit_engine.static_analyzer import analyze_repo
from audit_engine.report_generator import generate_report, save_report, get_repo_commit_info
from audit_engine.trust_verifier import (
    extract_trust_assumptions, verify_trust_assumptions, apply_downgrade,
)
from configs.audit_config import AUDIT_AGENT_VERSION

app = Flask(
    __name__,
    template_folder=os.path.join(PROJECT_ROOT, "web_app", "templates"),
    static_folder=os.path.join(PROJECT_ROOT, "web_app", "static"),
)

AUDIT_RESULTS_DIR = os.path.join(PROJECT_ROOT, "audit_results")
CLONE_DIR = os.path.join(PROJECT_ROOT, "cloned_repos")

# 正在进行中的审计任务 {task_id: {"status": ..., "progress": queue.Queue}}
active_tasks = {}


# ============================================================
# 工具函数
# ============================================================

def parse_github_url(url: str) -> tuple:
    """从 GitHub URL 提取 owner、repo 名称和可选的子目录路径
    返回 (owner, repo, subdir) — subdir 可为 None
    支持格式:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      https://github.com/owner/repo/tree/branch/path/to/dir
      github.com/owner/repo
      owner/repo
    """
    url = url.strip().rstrip("/")
    # 排除常见的非 GitHub 链接误用
    blacklist = ["google.com", "bing.com", "baidu.com", "search?"]
    if any(b in url.lower() for b in blacklist):
        return None, None, None

    # 带子目录的完整 URL: /owner/repo/tree/branch/subdir...
    m = re.match(
        r"(?:https?://)?github\.com/([^/]+)/([^/]+)/tree/[^/]+/(.+)$",
        url
    )
    if m:
        owner = m.group(1)
        repo = m.group(2).split('?')[0].split('#')[0]
        subdir = m.group(3).split('?')[0].split('#')[0]
        return owner, repo, subdir

    # 普通仓库根 URL
    m = re.match(r"(?:https?://)?github\.com/([^/]+)/([^/.]+?)(?:\.git)?$", url)
    if m:
        owner, repo = m.group(1), m.group(2)
        repo = repo.split('?')[0].split('#')[0]
        return owner, repo, None

    # owner/repo 简写
    m = re.match(r"^([^/]+)/([^/]+)$", url)
    if m:
        owner, repo = m.group(1), m.group(2)
        repo = repo.split('?')[0].split('#')[0]
        return owner, repo, None

    return None, None, None


def find_cached_report(owner: str, repo: str, subdir: str = "") -> dict | None:
    """查找已缓存的审计报告（最新版本）"""
    # 用 subdir 区分同一仓库不同路径的缓存
    repo_slug = repo + ("__" + subdir.strip("/").replace("/", "__") if subdir else "")
    repo_dir = os.path.join(AUDIT_RESULTS_DIR, owner, repo_slug)
    if not os.path.exists(repo_dir):
        return None

    # 遍历 commit hash 目录，找最新的报告
    latest_report = None
    latest_time = 0

    for commit_dir in os.listdir(repo_dir):
        commit_path = os.path.join(repo_dir, commit_dir)
        if not os.path.isdir(commit_path):
            continue

        report_file = os.path.join(commit_path, f"{AUDIT_AGENT_VERSION}_audit_report.md")
        meta_file = os.path.join(commit_path, f"{AUDIT_AGENT_VERSION}_audit_meta.json")

        if os.path.exists(report_file):
            mtime = os.path.getmtime(report_file)
            if mtime > latest_time:
                latest_time = mtime
                report_md = ""
                meta = {}
                try:
                    with open(report_file, "r", encoding="utf-8") as f:
                        report_md = f.read()
                except Exception:
                    pass
                try:
                    if os.path.exists(meta_file):
                        with open(meta_file, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                except Exception:
                    pass
                latest_report = {
                    "report_md": report_md,
                    "meta": meta,
                    "commit": commit_dir,
                    "cached": True,
                    "cached_at": datetime.fromtimestamp(mtime).isoformat(),
                }

    return latest_report


def check_repo_size(owner: str, repo: str) -> tuple[int, str]:
    """用 GitHub API 检查仓库大小（KB），返回 (size_kb, error)"""
    try:
        import urllib.request
        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        req = urllib.request.Request(api_url, headers={"User-Agent": "skill-audit-agent"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("size", 0), ""
    except Exception as e:
        return 0, str(e)


def clone_repo(url: str, subdir: str = "") -> tuple[str, str]:
    """浅克隆 GitHub 仓库（支持稀疏克隆子目录），返回 (本地路径, 错误信息)"""
    import shutil
    repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
    repo_path = os.path.join(CLONE_DIR, repo_name)

    os.makedirs(CLONE_DIR, exist_ok=True)

    # 如果文件夹已存在，检查是否可用，否则清理掉
    if os.path.exists(repo_path):
        if os.path.exists(os.path.join(repo_path, ".git")):
            # 有 .git 但如果需要子目录，验证子目录确实存在
            if subdir:
                target = os.path.join(repo_path, subdir.strip("/"))
                if os.path.exists(target) and os.listdir(target):
                    print(f"[*] Repository exists with valid subdir '{subdir}': {repo_path}")
                    return repo_path, ""
                else:
                    print(f"[*] Repository exists but subdir '{subdir}' missing/empty, re-cloning...")
                    try:
                        shutil.rmtree(repo_path)
                    except Exception as e:
                        return None, f"无法清理旧目录: {str(e)}"
            else:
                print(f"[*] Repository already exists and is valid: {repo_path}")
                return repo_path, ""
        else:
            print(f"[*] Path exists but is not a git repo, removing: {repo_path}")
            try:
                shutil.rmtree(repo_path)
            except Exception as e:
                return None, f"无法清理旧目录: {str(e)}"

    print(f"[*] Cloning {url} to {repo_path}...")
    try:
        # 使用环境变量禁止 Git 弹出交互式提示 (credential prompts)
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_ASKPASS"] = "true"

        if subdir:
            # 稀疏克隆：只下载指定子目录
            print(f"[*] Sparse clone: only fetching subdir '{subdir}'")
            sparse_dir = subdir.strip("/")

            # 正确顺序：init → remote add → sparse-checkout config → fetch → checkout
            cmds = [
                ["git", "init", repo_path],
                ["git", "-C", repo_path, "remote", "add", "origin", url],
                ["git", "-C", repo_path, "config", "core.sparseCheckout", "true"],
            ]
            for cmd in cmds:
                r = subprocess.run(cmd, capture_output=True, timeout=30, env=env)
                if r.returncode != 0:
                    shutil.rmtree(repo_path, ignore_errors=True)
                    return None, r.stderr.decode(errors="ignore").strip()

            # 写入 sparse-checkout 配置文件（指定要拉取的子目录）
            sparse_file = os.path.join(repo_path, ".git", "info", "sparse-checkout")
            os.makedirs(os.path.dirname(sparse_file), exist_ok=True)
            with open(sparse_file, "w") as f:
                f.write(f"{sparse_dir}/\n")

            # fetch + checkout
            fetch_result = subprocess.run(
                ["git", "-C", repo_path, "fetch", "--depth", "1", "origin", "HEAD"],
                capture_output=True, timeout=120, env=env
            )
            if fetch_result.returncode != 0:
                shutil.rmtree(repo_path, ignore_errors=True)
                return None, fetch_result.stderr.decode(errors="ignore").strip()

            checkout_result = subprocess.run(
                ["git", "-C", repo_path, "checkout", "FETCH_HEAD"],
                capture_output=True, timeout=60, env=env
            )
            if checkout_result.returncode != 0:
                shutil.rmtree(repo_path, ignore_errors=True)
                return None, checkout_result.stderr.decode(errors="ignore").strip()

            # 验证子目录确实存在
            target = os.path.join(repo_path, sparse_dir)
            if not os.path.exists(target):
                # 列出实际文件帮助调试
                actual = os.listdir(repo_path) if os.path.exists(repo_path) else []
                shutil.rmtree(repo_path, ignore_errors=True)
                return None, f"子目录 '{sparse_dir}' 不存在，仓库实际包含: {actual[:10]}"
        else:
            # 普通浅克隆（带超时120s）
            result = subprocess.run(
                ["git", "clone", "--depth", "1", url, repo_path],
                check=False,
                capture_output=True,
                timeout=120,
                env=env
            )
            if result.returncode != 0:
                error_msg = result.stderr.decode(errors="ignore").strip()
                print(f"[!] Git Clone Failed: {error_msg}")
                if os.path.exists(repo_path):
                    shutil.rmtree(repo_path)
                return None, error_msg

        return repo_path, ""
    except Exception as e:
        print(f"[!] Clone Exception: {str(e)}")
        if os.path.exists(repo_path):
            try: shutil.rmtree(repo_path)
            except: pass
        return None, str(e)


def run_audit(owner: str, repo: str, repo_path: str, progress_q: queue.Queue, subdir: str = "") -> dict:
    """执行完整审计并通过 queue 发送进度"""
    try:
        progress_q.put({"step": "commit", "message": "获取 commit 信息..."})
        commit_info = get_repo_commit_info(repo_path)

        progress_q.put({"step": "static", "message": "静态分析中...", "pct": 20})
        static_results, scan_stats = analyze_repo(repo_path)

        total_findings = sum(len(r.findings) for r in static_results if hasattr(r, 'findings'))
        progress_q.put({
            "step": "static_done",
            "message": f"静态分析完成：发现 {total_findings} 个问题",
            "pct": 60,
        })

        # 上下文提取
        progress_q.put({"step": "context", "message": "提取 Skill 上下文...", "pct": 70})
        from audit_engine.pipeline import extract_skill_context
        skill_context = extract_skill_context(repo_path)

        # Phase 3: LLM 深度审查
        llm_results = []
        openrouter_key = os.environ.get("OPENROUTER_API_KEY", "")
        files_with_findings = [r for r in static_results if hasattr(r, 'findings') and r.findings]
        # 最多审查2个文件，防止超时
        files_with_findings = files_with_findings[:2]
        if openrouter_key and files_with_findings:
            try:
                from audit_engine.llm_reviewer import MultiModelReviewer
                reviewer = MultiModelReviewer()
                total_files = len(files_with_findings)
                for idx, file_result in enumerate(files_with_findings):
                    pct = 70 + int((idx / total_files) * 13)  # 70% → 83%
                    progress_q.put({
                        "step": "llm",
                        "message": f"LLM 深度审查 ({idx+1}/{total_files}): {getattr(file_result, 'filepath', '')}...",
                        "pct": pct,
                    })
                    findings_dicts = [f.to_dict() if hasattr(f, 'to_dict') else vars(f) for f in file_result.findings]
                    filepath = getattr(file_result, 'filepath', '')
                    language = getattr(file_result, 'language', 'python')
                    full_path = os.path.join(repo_path, filepath)
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='replace') as fp:
                            file_content = fp.read()
                    except Exception:
                        file_content = ""
                    consensus = reviewer.review_finding(
                        filepath=filepath,
                        language=language,
                        static_findings=findings_dicts,
                        code_context=file_content[:3000],
                        file_content=file_content,
                        skill_context=skill_context,
                    )
                    llm_results.append(consensus)
            except Exception as llm_err:
                progress_q.put({"step": "llm_warn", "message": f"LLM 审查部分失败: {str(llm_err)}", "pct": 83})

        # Trust Chain + 假设验证 + 风险降级（与 pipeline 行为一致）
        progress_q.put({"step": "trust", "message": "信任链分析与假设验证...", "pct": 85})
        trust_chain_result = {}
        try:
            if openrouter_key:
                from audit_engine.llm_reviewer import run_trust_chain_analysis, LLMClient
                from configs.audit_config import LLM_CONFIGS

                tc_config = LLM_CONFIGS.get("security_analyst", list(LLM_CONFIGS.values())[0])
                tc_client = LLMClient(provider=tc_config.get("provider", "openrouter"))

                all_files_content = {}
                for sr in static_results[:8]:
                    file_rel = getattr(sr, 'file', None) or getattr(sr, 'filepath', None)
                    if not file_rel:
                        continue
                    full_path = os.path.join(repo_path, file_rel)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                            all_files_content[file_rel] = fh.read()
                    except Exception:
                        pass

                trust_chain_result = run_trust_chain_analysis(
                    all_files_content=all_files_content,
                    skill_context=skill_context[:3000],
                    llm_client=tc_client,
                    model=tc_config["model"],
                )

                assumptions = extract_trust_assumptions(trust_chain_result)
                if assumptions:
                    def _progress(i, total, a):
                        progress_q.put({
                            "step": "trust_verify",
                            "message": f"验证信任假设 ({i+1}/{total}): {a.subject}",
                            "pct": 86 + int(((i + 1) / max(total, 1)) * 3),
                        })

                    assumptions = verify_trust_assumptions(assumptions, progress_callback=_progress)
                    llm_results, _ = apply_downgrade(llm_results, assumptions)
                    trust_chain_result["trust_assumption_results"] = [a.to_dict() for a in assumptions]
        except Exception as trust_err:
            progress_q.put({"step": "trust_warn", "message": f"信任链分析失败，跳过: {str(trust_err)}", "pct": 88})
            trust_chain_result = {}

        # 生成报告
        progress_q.put({"step": "report", "message": "生成报告...", "pct": 90})
        # subdir 有值时，URL 和 repo 名都精确到子目录
        if subdir:
            skill_url = f"https://github.com/{owner}/{repo}/tree/main/{subdir.strip('/')}"
            skill_repo_label = f"{repo}/{subdir.strip('/')}"
        else:
            skill_url = f"https://github.com/{owner}/{repo}"
            skill_repo_label = repo
        markdown, meta = generate_report(
            skill_owner=owner,
            skill_repo=skill_repo_label,
            skill_url=skill_url,
            commit_info=commit_info,
            audit_version=AUDIT_AGENT_VERSION,
            static_results=static_results,
            llm_results=llm_results,
            scenario_results=[],
            scan_stats=scan_stats.to_dict() if hasattr(scan_stats, 'to_dict') else {},
            trust_chain_result=trust_chain_result,
        )

        # 保存报告（用 repo_slug 区分子目录）
        repo_slug = repo + ("__" + subdir.strip("/").replace("/", "__") if subdir else "")
        os.makedirs(AUDIT_RESULTS_DIR, exist_ok=True)
        save_report(
            output_dir=AUDIT_RESULTS_DIR,
            skill_owner=owner,
            skill_repo=repo_slug,
            commit_hash=commit_info.get("commit_hash", "unknown"),
            audit_version=AUDIT_AGENT_VERSION,
            markdown=markdown,
            meta=meta,
        )

        progress_q.put({"step": "done", "message": "审计完成!", "pct": 100})

        return {
            "report_md": markdown,
            "meta": meta,
            "commit": commit_info.get("commit_hash", "unknown")[:12],
            "cached": False,
        }

    except Exception as e:
        progress_q.put({"step": "error", "message": f"审计失败: {str(e)}", "pct": 0})
        return {"error": str(e)}


# ============================================================
# 路由
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/audit", methods=["POST"])
def api_audit():
    """提交审计请求"""
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "请输入 GitHub 仓库地址"}), 400

    owner, repo, subdir = parse_github_url(url)
    if not owner or not repo:
        return jsonify({"error": "无效的 GitHub 地址。支持格式: https://github.com/owner/repo 或 https://github.com/owner/repo/tree/branch/subdir"}), 400

    # 1. 检查缓存
    cached = find_cached_report(owner, repo, subdir or "")
    if cached:
        return jsonify(cached)

    # 2. 克隆仓库
    github_url = f"https://github.com/{owner}/{repo}"
    repo_path, clone_err = clone_repo(github_url, subdir=subdir or "")
    if not repo_path:
        return jsonify({"error": f"克隆仓库失败: {clone_err or github_url}"}), 500

    # 子目录模式：审计路径指向子目录
    audit_path = os.path.join(repo_path, subdir) if subdir else repo_path
    if not os.path.exists(audit_path):
        return jsonify({"error": f"子目录不存在: {subdir}"}), 400

    # 3. 同步执行审计（静态分析通常很快）
    progress_q = queue.Queue()
    result = run_audit(owner, repo, audit_path, progress_q, subdir=subdir or "")

    if "error" in result:
        return jsonify({"error": result["error"]}), 500

    return jsonify(result)


@app.route("/api/audit/stream", methods=["POST"])
def api_audit_stream():
    """SSE 流式审计 — 实时返回进度"""
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "请输入 GitHub 仓库地址"}), 400

    owner, repo, subdir = parse_github_url(url)
    if not owner or not repo:
        return jsonify({"error": "无效的 GitHub 地址。支持格式: https://github.com/owner/repo 或 https://github.com/owner/repo/tree/branch/subdir"}), 400

    # 检查缓存
    cached = find_cached_report(owner, repo, subdir or "")
    if cached:
        def cached_stream():
            yield f"data: {json.dumps({'step': 'cached', 'message': '命中缓存！直接返回已有报告', 'pct': 100})}\n\n"
            yield f"data: {json.dumps({'step': 'result', 'data': cached})}\n\n"
        
        headers = {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
        return Response(stream_with_context(cached_stream()), mimetype="text/event-stream", headers=headers)

    # 流式审计
    print(f"[*] Starting audit stream for: {url}")
    progress_q = queue.Queue()

    def generate():
        github_url = f"https://github.com/{owner}/{repo}"
        clone_label = f"{owner}/{repo}" + (f"/{subdir}" if subdir else "")

        # 大小检查
        yield f"data: {json.dumps({'step': 'init', 'message': f'正在检查仓库 {clone_label}...', 'pct': 2})}\n\n"
        size_kb, size_err = check_repo_size(owner, repo)
        MAX_SIZE_KB = 100 * 1024  # 100 MB
        if not size_err and size_kb > MAX_SIZE_KB:
            size_mb = size_kb // 1024
            msg = f"仓库过大（{size_mb} MB），超过 100 MB 限制。建议指定子目录，例如：https://github.com/{owner}/{repo}/tree/main/某个子目录"
            yield f"data: {json.dumps({'step': 'error', 'message': msg})}\n\n"
            print(f"[!] Repo too large: {size_mb} MB")
            return
        print(f"[*] Repo size: {size_kb} KB — OK")

        # 克隆阶段
        print(f"[*] Step 1: Cloning {github_url}")
        clone_msg = f"正在{'稀疏' if subdir else ''}克隆仓库 {clone_label}..."
        yield f"data: {json.dumps({'step': 'clone', 'message': clone_msg, 'pct': 5})}\n\n"

        repo_path, clone_err = clone_repo(github_url, subdir=subdir)
        if not repo_path:
            error_msg = f"克隆仓库失败: {clone_err}"
            yield f"data: {json.dumps({'step': 'error', 'message': error_msg})}\n\n"
            print(f"[!] Error: {error_msg}")
            return

        # 子目录模式
        audit_path = os.path.join(repo_path, subdir) if subdir else repo_path
        if not os.path.exists(audit_path):
            yield f"data: {json.dumps({'step': 'error', 'message': f'子目录不存在: {subdir}'})}\n\n"
            return

        print(f"[*] Repo cloned to: {repo_path}, audit path: {audit_path}")
        yield f"data: {json.dumps({'step': 'clone_done', 'message': '仓库克隆完成', 'pct': 15})}\n\n"

        # 在线程中运行审计
        print(f"[*] Step 2: Running audit thread")
        result_holder = [None]

        def audit_thread():
            result_holder[0] = run_audit(owner, repo, audit_path, progress_q, subdir=subdir or "")

        t = threading.Thread(target=audit_thread)
        t.start()

        # 转发进度事件（每5秒发心跳注释，防止代理超时断连）
        last_heartbeat = time.time()
        while t.is_alive() or not progress_q.empty():
            try:
                msg = progress_q.get(timeout=0.5)
                yield f"data: {json.dumps(msg)}\n\n"
                last_heartbeat = time.time()
            except queue.Empty:
                if time.time() - last_heartbeat > 5:
                    yield ": heartbeat\n\n"
                    last_heartbeat = time.time()
                continue

        # 发送最终结果
        if result_holder[0] and "error" not in result_holder[0]:
            print(f"[*] Audit completed successfully for {owner}/{repo}")
            yield f"data: {json.dumps({'step': 'result', 'data': result_holder[0]})}\n\n"
        elif result_holder[0]:
            print(f"[!] Audit failed for {owner}/{repo}: {result_holder[0].get('error')}")
            yield f"data: {json.dumps({'step': 'error', 'message': result_holder[0].get('error', '未知错误')})}\n\n"

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return Response(stream_with_context(generate()), mimetype="text/event-stream", headers=headers)


@app.route("/api/cache")
def api_cache_list():
    """列出所有已缓存的审计结果"""
    results = []
    if not os.path.exists(AUDIT_RESULTS_DIR):
        return jsonify(results)

    for owner_dir in sorted(os.listdir(AUDIT_RESULTS_DIR)):
        owner_path = os.path.join(AUDIT_RESULTS_DIR, owner_dir)
        if not os.path.isdir(owner_path) or owner_dir.startswith("."):
            continue
        for repo_dir in sorted(os.listdir(owner_path)):
            repo_path = os.path.join(owner_path, repo_dir)
            if not os.path.isdir(repo_path):
                continue
            # 找最新 meta
            for commit_dir in os.listdir(repo_path):
                meta_file = os.path.join(repo_path, commit_dir, f"{AUDIT_AGENT_VERSION}_audit_meta.json")
                if os.path.exists(meta_file):
                    try:
                        with open(meta_file, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                        results.append({
                            "owner": owner_dir,
                            "repo": repo_dir,
                            "commit": commit_dir[:12],
                            "risk": meta.get("overall_risk", "UNKNOWN"),
                            "findings": meta.get("total_findings", 0),
                            "date": meta.get("audit_date", ""),
                        })
                    except Exception:
                        pass

    return jsonify(results)


if __name__ == "__main__":
    os.makedirs(AUDIT_RESULTS_DIR, exist_ok=True)
    os.makedirs(CLONE_DIR, exist_ok=True)
    port = int(os.environ.get("PORT", 5000))
    print("=" * 50)
    print("  Skill Audit Web Server")
    print(f"  http://localhost:{port}")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=port)
