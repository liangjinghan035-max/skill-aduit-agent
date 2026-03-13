# Skill Audit Tool Upgrade Plan

This plan addresses the three critical core issues identified in the current version of the skill audit tool: missing semantic rules for Prompts, skipping tool configurations, and the GPT-4o truncation bug.

## User Review Required

Please review the proposed architectural changes and the verification plan below. 

## Proposed Changes

### audit_engine/pipeline.py
**Goal:** Ensure all `skill_prompt` files are reviewed by the semantic LLM evaluator, even if they bypass static analysis rules.
#### [MODIFY] pipeline.py
- Modify the `files_with_findings` filtering logic in [audit_single_repo](file:///e:/starchild%E6%96%B0%E5%8A%A0%E5%9D%A1%E5%AE%9E%E4%B9%A0/skill-audit-agent/audit_engine/pipeline.py#138-341).
- Change the condition to always include the file if its language is `"skill_prompt"` or `"tool_config"`, so that the LLM reviews these critical files directly instead of relying solely on static findings.

### audit_engine/llm_reviewer.py
**Goal:** Implement LLM-as-a-Judge capabilities specifically for Prompts, and fix the `adversarial_analyst` prompt truncation bug.
#### [MODIFY] llm_reviewer.py
- **Fix GPT-4o Truncation Bug:** In `ADVERSARIAL_ANALYST_PROMPT`, change `"summary": "Attack perspective analysis"` to `"summary": "One paragraph analysis from an attack perspective"`. The hardcoded string is causing the model to output a literal placeholder and often truncate its output.
- **Skill Prompt Evaluation:** Create a new prompt template or modify the existing `SECURITY_ANALYST_PROMPT` and `ADVERSARIAL_ANALYST_PROMPT` to inject specific instructions when `language == "skill_prompt"`. The LLM will be explicitly instructed to search for:
  - Prompt Injection Vulnerabilities
  - Jailbreak Backdoors
  - Data Exfiltration Instructions

### audit_engine/static_analyzer.py
**Goal:** Extend the analyzer to support tool configurations ([.json](file:///e:/starchild%E6%96%B0%E5%8A%A0%E5%9D%A1%E5%AE%9E%E4%B9%A0/skill-audit-agent/self_test_results.json), `.yml`, `.yaml`) and detect high-risk tool declarations.
#### [MODIFY] static_analyzer.py
- Add [.json](file:///e:/starchild%E6%96%B0%E5%8A%A0%E5%9D%A1%E5%AE%9E%E4%B9%A0/skill-audit-agent/self_test_results.json), `.yml`, and `.yaml` to `LANG_MAP` and `SUPPORTED_CODE_EXTENSIONS` mapping to a new language type `"tool_config"`.
- Implement a new `analyze_tool_config(filepath, content)` function.
- The function will attempt to parse the JSON or YAML. If it finds tool configurations (e.g. keys like `tools`, `permissions`, `command`), it will search for high-risk capabilities like `"shell"`, `"exec"`, `"bash"`, `"subprocess"` and generate static findings. 

## Verification Plan

### Automated/Manual Testing
1. **Self-Test the Upgrades:** Run the modified scanner over local [.md](file:///e:/starchild%E6%96%B0%E5%8A%A0%E5%9D%A1%E5%AE%9E%E4%B9%A0/skill-audit-agent/USAGE.md), [.json](file:///e:/starchild%E6%96%B0%E5%8A%A0%E5%9D%A1%E5%AE%9E%E4%B9%A0/skill-audit-agent/self_test_results.json), and `.yml` test fixtures or existing `test_fixtures` (if available in the `e:\starchild新加坡实习\skill-audit-agent\test_fixtures` directory) to verify the new behaviors.
2. **GPT-4o Bug Verification:** Run a sample audit utilizing the OpenRouter API (if configured) or check the generated reports to ensure `adversarial_analyst` is naturally producing paragraphs rather than the truncated literal template string.
3. **Parse Tool Configs Check:** Create a fake `malicious_tool.json` file assigning the "shell" string to a tool, run the audit, and confirm the tool flags finding #1 on the configuration file.
