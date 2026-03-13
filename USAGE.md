# Skill Audit Agent - 使用指南

## 1. 环境准备

### 最低要求
- Python 3.10+（代码使用了 `list[str]` 等新语法）
- Git（用于克隆目标仓库）
- **零 pip 依赖** — 所有 API 调用用 Python 标准库 `urllib`

### 设置 OpenRouter API Key（开启 LLM 审查时需要）

去 https://openrouter.ai/keys 创建 key，然后：
```bash
export OPENROUTER_API_KEY="sk-or-v1-xxxxxxxxxxxxxxxx"
```

**不设 key 也能跑** — 静态分析（`--no-llm`）完全免费，不需要任何 API key。

### 可选：换模型

默认配置在 `configs/audit_config.py` 中，Gold Agent 用 3 个不同模型交叉验证：

```python
LLM_CONFIGS = {
    "security_analyst":    {"model": "anthropic/claude-sonnet-4"},     # 安全分析
    "intent_analyst":      {"model": "google/gemini-2.5-flash"},       # 意图分析
    "adversarial_analyst": {"model": "openai/gpt-4o"},                 # 红队模拟
}
```

你可以换成任何 OpenRouter 支持的模型，完整列表见 https://openrouter.ai/models
比如全用便宜的：
```python
"model": "google/gemini-2.5-flash"     # 每个角色都用 flash，省钱
```
或者全用最强的：
```python
"model": "anthropic/claude-sonnet-4"   # 每个角色都用 Claude，最准
```

---

## 2. 运行方式

项目有 **4 种运行模式**：

### 模式 A：自测（验证审计器本身是否正常）

```bash
cd skill-audit-agent

# 基础自测（仅静态分析，无需 API key）
python -m tests.run_self_test --static-only

# 详细输出（显示每个 finding 的具体内容）
python -m tests.run_self_test --static-only --verbose
```

预期输出：
```
RESULTS: 11/11 tests passed
  Detection Rate (malicious):    6/6 = 100%
  False Positive Rate (safe):    0/2 = 0%
  Gray Area Detection:           3/3 = 100%
```

### 模式 B：审计单个 GitHub 仓库

```bash
# 从 URL 克隆并审计（仅静态分析，免费）
python -m audit_engine.pipeline \
  --url https://github.com/some-owner/some-skill \
  --no-llm \
  --output ./audit_results

# 完整审计（含 LLM 交叉验证）
python -m audit_engine.pipeline \
  --url https://github.com/some-owner/some-skill \
  --output ./audit_results
```

### 模式 C：审计本地仓库

```bash
python -m audit_engine.pipeline \
  --repo /path/to/local/repo \
  --owner owner_name \
  --name repo_name \
  --no-llm \
  --output ./audit_results
```

### 模式 D：发现 skill（从 VoltAgent awesome-list 自动提取）

```bash
# 先看看能发现多少 skill（克隆两个索引仓库，提取 .md 中的 GitHub 链接）
python -m audit_engine.pipeline --discover-only

# 会输出类似:
#   1. owner-a/skill-foo
#   2. owner-b/skill-bar
#   3. ...
```

### 模式 E：批量审计（发现 + 审计 一条龙）

```bash
# 自动发现 skill → 克隆 → 逐个审计（先试 5 个）
python -m audit_engine.pipeline --batch \
  --max-repos 5 \
  --no-llm \
  --output ./audit_results

# 全量审计（发现多少审计多少，含 LLM）
export OPENROUTER_API_KEY="sk-or-v1-..."
python -m audit_engine.pipeline --batch \
  --output ./audit_results

# 强制重新发现（忽略缓存）
python -m audit_engine.pipeline --batch --refresh --max-repos 10 \
  --output ./audit_results
```

---

## 3. 输出文件说明

审计完成后，`audit_results/` 目录结构如下：

```
audit_results/
├── _index.json                              # 全局索引（所有审计记录）
├── anthropics/
│   └── anthropic-cookbook/
│       └── a1b2c3d4e5f6/                    # commit hash 前 12 位
│           ├── V1_audit_report.md            # 可读的审计报告
│           └── V1_audit_meta.json            # 机器可读的元数据
├── KillianLucas/
│   └── open-interpreter/
│       └── 7890abcdef12/
│           ├── V1_audit_report.md
│           └── V1_audit_meta.json
```

### 报告内容包括：
- **Severity Summary** — CRITICAL/HIGH/MEDIUM/LOW/SAFE 统计
- **Detailed Findings** — 每个发现的文件、行号、代码上下文、严重程度
- **LLM Cross-Validation** — 三个 AI 角色的独立判断 + 共识结论
- **Gray Area Analysis** — 灰色地带的正确用法 vs 危险用法详细说明
- **Scenario Simulation** — 正常使用/对抗输入/权限提升/数据外泄 四种场景模拟

---

## 4. CLI 参数完整列表

```
python -m audit_engine.pipeline --help

运行模式（四选一）:
  --repo PATH         审计本地仓库
  --url URL           克隆 GitHub URL 并审计
  --batch             从 VoltAgent awesome-list 发现 skill → 批量审计
  --discover-only     仅发现 skill（打印列表，不审计）

通用选项:
  --owner NAME        仓库所有者（报告用）
  --name NAME         仓库名称（报告用）
  --output DIR        报告输出目录（默认 ./audit_results）
  --clone-dir DIR     克隆仓库存放目录（默认 ./cloned_repos）
  --no-llm            禁用 LLM 审查（仅静态分析，免费）
  --no-scenarios      禁用场景模拟
  --max-repos N       批量模式下最多审计 N 个仓库
  --refresh           强制重新发现 skill（忽略缓存）
```

---

## 5. 使用建议

### 第一步：确认自测通过
```bash
python -m tests.run_self_test --static-only -v
```

### 第二步：发现 skill（看看两个 awesome-list 里有多少）
```bash
python -m audit_engine.pipeline --discover-only
```

### 第三步：先对 3 个 skill 做静态分析（免费试水）
```bash
python -m audit_engine.pipeline --batch --max-repos 3 --no-llm --output ./audit_results
```

### 第四步：挑 1-2 个加上 LLM 做完整审计
```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
python -m audit_engine.pipeline \
  --url https://github.com/某个发现的skill \
  --output ./audit_results
```

### 第五步：批量跑全部
```bash
python -m audit_engine.pipeline --batch --output ./audit_results
```

### 第六步：把 audit_results/ 推到 GitHub 公开仓库
```bash
cd audit_results
git init
git add .
git commit -m "Audit results V1 - $(date +%Y-%m-%d)"
git remote add origin https://github.com/YOUR_ORG/skill-audit-results.git
git push -u origin main
```

---

## 6. 费用估算

| 模式 | 费用 | 速度 | 准确度 |
|------|------|------|--------|
| 仅静态分析 (`--no-llm`) | 免费 | ~5秒/仓库 | 检出率 100%, 但有少量假阳性需人工确认 |
| 单模型 LLM | ~$0.05/文件 | ~30秒/文件 | 好 |
| Gold Agent (3模型交叉) | ~$0.15/文件 | ~90秒/文件 | 最好，接近人工审计 |

批量审计 20 个仓库（假设每个仓库 ~50 个需审查的文件）：
- 仅静态：免费，~2 分钟
- Gold Agent：~$150，~4 小时
