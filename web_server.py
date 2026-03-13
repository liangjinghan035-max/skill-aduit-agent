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
    """从 GitHub URL 提取 owner 和 repo 名称"""
    url = url.strip().rstrip("/")
    # 支持格式:
    # https://github.com/owner/repo
    # https://github.com/owner/repo.git
    # github.com/owner/repo
    # owner/repo
    patterns = [
        r"(?:https?://)?github\.com/([^/]+)/([^/.]+?)(?:\.git)?$",
        r"^([^/]+)/([^/]+)$",
    ]
    for pat in patterns:
        m = re.match(pat, url)
        if m:
            return m.group(1), m.group(2)
    return None, None


def find_cached_report(owner: str, repo: str) -> dict | None:
    """查找已缓存的审计报告（最新版本）"""
    repo_dir = os.path.join(AUDIT_RESULTS_DIR, owner, repo)
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


def clone_repo(url: str) -> str | None:
    """浅克隆 GitHub 仓库，返回本地路径"""
    repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
    repo_path = os.path.join(CLONE_DIR, repo_name)

    os.makedirs(CLONE_DIR, exist_ok=True)

    if os.path.exists(repo_path):
        return repo_path

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, repo_path],
            check=True, capture_output=True, timeout=120,
        )
        return repo_path
    except Exception:
        return None


def run_audit(owner: str, repo: str, repo_path: str, progress_q: queue.Queue) -> dict:
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

        # 生成报告
        progress_q.put({"step": "report", "message": "生成报告...", "pct": 85})
        skill_url = f"https://github.com/{owner}/{repo}"
        markdown, meta = generate_report(
            skill_owner=owner,
            skill_repo=repo,
            skill_url=skill_url,
            commit_info=commit_info,
            audit_version=AUDIT_AGENT_VERSION,
            static_results=static_results,
            llm_results=[],
            scenario_results=[],
            scan_stats=scan_stats.to_dict() if hasattr(scan_stats, 'to_dict') else {},
        )

        # 保存报告
        os.makedirs(AUDIT_RESULTS_DIR, exist_ok=True)
        save_report(
            output_dir=AUDIT_RESULTS_DIR,
            skill_owner=owner,
            skill_repo=repo,
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

    owner, repo = parse_github_url(url)
    if not owner or not repo:
        return jsonify({"error": "无效的 GitHub 地址。支持格式: https://github.com/owner/repo 或 owner/repo"}), 400

    # 1. 检查缓存
    cached = find_cached_report(owner, repo)
    if cached:
        return jsonify(cached)

    # 2. 克隆仓库
    github_url = f"https://github.com/{owner}/{repo}"
    repo_path = clone_repo(github_url)
    if not repo_path:
        return jsonify({"error": f"克隆仓库失败: {github_url}"}), 500

    # 3. 同步执行审计（静态分析通常很快）
    progress_q = queue.Queue()
    result = run_audit(owner, repo, repo_path, progress_q)

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

    owner, repo = parse_github_url(url)
    if not owner or not repo:
        return jsonify({"error": "无效的 GitHub 地址"}), 400

    # 检查缓存
    cached = find_cached_report(owner, repo)
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

        # 克隆阶段
        print(f"[*] Step 1: Cloning {github_url}")
        yield f"data: {json.dumps({'step': 'clone', 'message': '正在克隆仓库...', 'pct': 5})}\n\n"

        repo_path = clone_repo(github_url)
        if not repo_path:
            yield f"data: {json.dumps({'step': 'error', 'message': '克隆仓库失败'})}\n\n"
            print(f"[!] Error: Failed to clone {github_url}")
            return

        print(f"[*] Repo cloned to: {repo_path}")
        yield f"data: {json.dumps({'step': 'clone_done', 'message': '仓库克隆完成', 'pct': 15})}\n\n"

        # 在线程中运行审计
        print(f"[*] Step 2: Running audit thread")
        result_holder = [None]

        def audit_thread():
            result_holder[0] = run_audit(owner, repo, repo_path, progress_q)

        t = threading.Thread(target=audit_thread)
        t.start()

        # 转发进度事件
        while t.is_alive() or not progress_q.empty():
            try:
                msg = progress_q.get(timeout=0.5)
                yield f"data: {json.dumps(msg)}\n\n"
            except queue.Empty:
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
