# Skill Audit Agent (SAA)

## 目标
构建一个高准确度的开源 Skill 安全审计 Agent，用于：
1. 对开源 AI Skill 进行深度安全审计（误报率 < 5%，漏报率 < 3%）
2. 对"灰色地带"代码给出详细的正确用法 vs 危险用法说明
3. 将审计结果发布到公开 GitHub 仓库，按 skill 路径 + commit + 审计版本分类

## 架构概览

```
┌────────────────────────────────────────────────────────┐
│                   Audit Pipeline (V1 - Gold)           │
├────────────────────────────────────────────────────────┤
│                                                        │
│  Phase 1: Static Analysis                              │
│    ├── Python AST deep scan                            │
│    ├── JS/TS AST scan (via tree-sitter or acorn)       │
│    ├── Regex pattern matching (expanded)               │
│    └── Dependency graph analysis                       │
│                                                        │
│  Phase 2: Contextual Analysis                          │
│    ├── Data flow tracking (source → sink)              │
│    ├── Permission scope analysis                       │
│    ├── Skill manifest / SKILL.md parsing               │
│    └── README intent extraction                        │
│                                                        │
│  Phase 3: LLM Deep Review (Multi-Model)                │
│    ├── Model A: Security-focused analysis              │
│    ├── Model B: Intent & legitimacy analysis           │
│    ├── Model C: Attack scenario simulation             │
│    └── Cross-model consensus scoring                   │
│                                                        │
│  Phase 4: Scenario Simulation                          │
│    ├── Normal usage simulation                         │
│    ├── Adversarial input simulation                    │
│    ├── Privilege escalation probing                    │
│    └── Data exfiltration path analysis                 │
│                                                        │
│  Phase 5: Report Generation                            │
│    ├── Per-file finding with evidence                  │
│    ├── Gray-area detailed explanation                  │
│    ├── Severity scoring (CRITICAL/HIGH/MEDIUM/LOW/SAFE)│
│    └── Structured markdown for GitHub publication      │
│                                                        │
└────────────────────────────────────────────────────────┘
```

## 审计结果仓库结构

```
audit-results/
├── claude/
│   └── claude-seo/
│       └── 3426...76ab/
│           ├── V1_audit_report.md
│           └── V1_audit_meta.json
├── anthropic/
│   └── skill-name/
│       └── commit-hash/
│           ├── V1_audit_report.md
│           └── V1_audit_meta.json
└── _index.json          # 全局索引
```

## 开发路线

### Phase 1: Gold Agent (当前)
- 20 个 skill 深度审计
- 多模型交叉验证
- 注入 bug 验证检测率
- 输出标准化报告

### Phase 2: Benchmark Dataset
- 用 Gold Agent 结果作为 ground truth
- 构建 evaluation dataset
- 明确 precision / recall 指标

### Phase 3: Fast Agent
- 单模型 + 优化 prompt
- 用 benchmark dataset 校准
- 大规模运行
