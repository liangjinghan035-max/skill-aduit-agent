"""
Skill 发现模块

从 VoltAgent 的两个 awesome-list 索引仓库中：
1. 克隆索引仓库
2. 扫描所有 .md 文件，提取 GitHub 链接
3. 去重、过滤、解析为 {owner, repo, url} 格式
4. 返回可供审计的 skill 列表
"""

import os
import re
import subprocess
import json
from typing import Optional

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from configs.audit_config import INDEX_REPOS, LINK_IGNORE_PATTERNS, MAX_SKILLS_PER_RUN


def clone_index_repo(url: str, clone_dir: str) -> Optional[str]:
    """浅克隆一个索引仓库，返回本地路径"""
    repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
    repo_path = os.path.join(clone_dir, repo_name)

    if os.path.exists(repo_path):
        print(f"  [skip] Index repo '{repo_name}' already cloned")
        return repo_path

    print(f"  [clone] {url}")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, repo_path],
            check=True, capture_output=True, timeout=120,
        )
        return repo_path
    except subprocess.CalledProcessError as e:
        print(f"  [error] Clone failed: {e.stderr.decode()[:200]}")
        return None
    except subprocess.TimeoutExpired:
        print(f"  [error] Clone timed out")
        return None


def extract_github_links(filepath: str) -> set[str]:
    """从单个 .md 文件中提取所有 GitHub 仓库链接"""
    links = set()
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # 匹配 https://github.com/owner/repo 格式
        raw_urls = re.findall(
            r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',
            content
        )

        for url in raw_urls:
            # 清理尾部字符
            url = url.rstrip(")/.,;:'\"")
            # 去掉 .git 后缀
            url = url.removesuffix(".git")
            # 只保留 owner/repo 两级，去掉更深路径
            parts = url.split("/")
            if len(parts) >= 5:
                url = "/".join(parts[:5])  # https://github.com/owner/repo
            links.add(url)
    except Exception as e:
        print(f"  [warn] Error reading {filepath}: {e}")

    return links


def _should_ignore(url: str) -> bool:
    """检查链接是否应该被忽略"""
    for pattern in LINK_IGNORE_PATTERNS:
        if pattern in url:
            return True
    return False


def _parse_github_url(url: str) -> Optional[dict]:
    """从 GitHub URL 解析出 owner 和 repo"""
    # https://github.com/owner/repo
    match = re.match(r'https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)', url)
    if not match:
        return None
    return {
        "owner": match.group(1),
        "repo": match.group(2),
        "url": url,
    }


def discover_skills(clone_dir: str, max_skills: int = None) -> list[dict]:
    """
    完整的 skill 发现流程：
    1. 克隆两个索引仓库
    2. 扫描 .md 文件提取链接
    3. 过滤、去重、解析
    4. 返回 [{owner, repo, url}, ...]

    参数:
        clone_dir: 克隆目录
        max_skills: 最多返回多少个 skill（None = 不限，0 = 用配置中的默认值）
    """
    if max_skills is None or max_skills == 0:
        max_skills = MAX_SKILLS_PER_RUN if MAX_SKILLS_PER_RUN > 0 else 9999

    os.makedirs(clone_dir, exist_ok=True)

    all_links = set()

    print("=" * 60)
    print("PHASE 0: Discovering skills from index repos")
    print("=" * 60)

    for idx_repo in INDEX_REPOS:
        url = idx_repo["url"]
        name = idx_repo["name"]
        print(f"\n  Processing: {name}")

        repo_path = clone_index_repo(url, clone_dir)
        if not repo_path:
            continue

        # 扫描所有 .md 文件
        md_count = 0
        for root, dirs, files in os.walk(repo_path):
            # 跳过 .git
            dirs[:] = [d for d in dirs if d != ".git"]
            for fname in files:
                if fname.endswith(".md"):
                    md_path = os.path.join(root, fname)
                    links = extract_github_links(md_path)
                    all_links.update(links)
                    md_count += 1

        print(f"  Scanned {md_count} .md files, running total: {len(all_links)} unique links")

    # 过滤
    filtered = []
    for url in sorted(all_links):
        if _should_ignore(url):
            continue
        parsed = _parse_github_url(url)
        if parsed:
            filtered.append(parsed)

    print(f"\n  After filtering: {len(filtered)} skill repos")

    # 截断
    if len(filtered) > max_skills:
        print(f"  Limiting to first {max_skills} (use --max-repos to change)")
        filtered = filtered[:max_skills]

    # 保存发现结果到 JSON（方便复用）
    discovery_file = os.path.join(clone_dir, "_discovered_skills.json")
    with open(discovery_file, "w", encoding="utf-8") as f:
        json.dump({
            "source_repos": [r["url"] for r in INDEX_REPOS],
            "total_discovered": len(all_links),
            "after_filter": len(filtered),
            "skills": filtered,
        }, f, indent=2, ensure_ascii=False)
    print(f"  Discovery results saved to {discovery_file}")

    return filtered


def load_discovered_skills(clone_dir: str) -> Optional[list[dict]]:
    """如果之前已经发现过，直接加载缓存"""
    discovery_file = os.path.join(clone_dir, "_discovered_skills.json")
    if not os.path.exists(discovery_file):
        return None
    try:
        with open(discovery_file, "r") as f:
            data = json.load(f)
        skills = data.get("skills", [])
        print(f"  Loaded {len(skills)} previously discovered skills from cache")
        return skills
    except Exception:
        return None


# ============================================================
# CLI 入口 —— 单独运行发现模块
# ============================================================

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Discover skills from VoltAgent awesome lists")
    parser.add_argument("--clone-dir", default="./cloned_repos", help="Clone directory")
    parser.add_argument("--max", type=int, default=0, help="Max skills to return (0=all)")
    parser.add_argument("--refresh", action="store_true", help="Force re-discovery (ignore cache)")
    args = parser.parse_args()

    clone_dir = os.path.abspath(args.clone_dir)

    if not args.refresh:
        cached = load_discovered_skills(clone_dir)
        if cached:
            print(f"\nFound {len(cached)} cached skills. Use --refresh to re-discover.")
            for i, s in enumerate(cached[:20], 1):
                print(f"  {i:2d}. {s['owner']}/{s['repo']}")
            if len(cached) > 20:
                print(f"  ... and {len(cached) - 20} more")
            exit(0)

    skills = discover_skills(clone_dir, max_skills=args.max or 0)

    print(f"\nDiscovered {len(skills)} skills:")
    for i, s in enumerate(skills, 1):
        print(f"  {i:2d}. {s['owner']}/{s['repo']}  ({s['url']})")
