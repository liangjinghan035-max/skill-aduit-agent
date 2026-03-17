"""
Trust Assumption Verifier
- 对 LLM 提取的信任假设逐条自动搜索验证
- 验证通过则降低关联风险等级，不再标记 CRITICAL
"""

import json
import os
import re
import gzip
import urllib.request
import urllib.parse
from dataclasses import dataclass, asdict, field
from typing import Optional

BRAVE_API_KEY = os.environ.get("BRAVE_API_KEY", "")
BRAVE_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"
_PROXY_HOST = os.environ.get("PROXY_HOST", "")
_PROXY_PORT = os.environ.get("PROXY_PORT", "")

# 针对头部协议维护“官方 API 域名”白名单（可持续扩展）
OFFICIAL_API_DOMAINS = {
    "1inch": ["api.1inch.dev", "api.1inch.io", "fusion.1inch.io", "1inch.dev", "1inch.io"],
}

OFFICIAL_DOC_URLS = {
    "1inch": [
        "https://1inch.dev/",
        "https://business.1inch.com/portal/documentation",
    ]
}


def _service_from_domain(domain: str) -> str:
    parts = domain.lower().split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _domain_matches_allowlist(domain: str, allowlist: list[str]) -> bool:
    d = domain.lower()
    for a in allowlist:
        a = a.lower()
        if d == a or d.endswith("." + a):
            return True
    return False


def _brave_search(query: str, count: int = 5) -> list[dict]:
    params = urllib.parse.urlencode({"q": query, "count": count})
    req = urllib.request.Request(
        f"{BRAVE_SEARCH_URL}?{params}",
        headers={"Accept": "application/json", "Accept-Encoding": "gzip",
                 "X-Subscription-Token": BRAVE_API_KEY},
    )
    if _PROXY_HOST and _PROXY_PORT:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({
                "http": f"http://{_PROXY_HOST}:{_PROXY_PORT}",
                "https": f"http://{_PROXY_HOST}:{_PROXY_PORT}"
            })
        )
    else:
        opener = urllib.request.build_opener()
    try:
        with opener.open(req, timeout=10) as resp:
            raw = resp.read()
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
            data = json.loads(raw.decode("utf-8"))
            return [{"title": r.get("title", ""), "url": r.get("url", ""),
                     "description": r.get("description", "")}
                    for r in data.get("web", {}).get("results", [])]
    except Exception:
        return []


@dataclass
class TrustAssumption:
    id: str
    category: str          # API_ENDPOINT / SERVICE_REPUTATION / CONTRACT_ADDRESS
    claim: str             # 假设陈述
    subject: str           # 被验证的主体
    related_risk_ids: list = field(default_factory=list)
    verified: Optional[bool] = None
    verification_confidence: float = 0.0
    verification_evidence: list = field(default_factory=list)
    verification_summary: str = ""
    downgrade_applied: bool = False

    def to_dict(self):
        return asdict(self)


def _verify_api_endpoint(assumption: TrustAssumption) -> tuple:
    subject = assumption.subject
    domain = subject.replace("https://", "").replace("http://", "").split("/")[0].lower()
    service_name = _service_from_domain(domain)

    results = _brave_search(f'"{domain}" official API documentation', 4)
    results += _brave_search(f'{service_name} official API endpoint', 3)

    evidence, score = [], 0.0

    allowlist = OFFICIAL_API_DOMAINS.get(service_name, [])
    has_allowlist = bool(allowlist)
    domain_pass = _domain_matches_allowlist(domain, allowlist) if has_allowlist else None

    # 先做“域名真伪”硬校验（如果存在该服务白名单）
    if has_allowlist:
        if domain_pass:
            score += 0.65
            evidence.append({
                "title": f"Domain allowlist match for {service_name}",
                "url": OFFICIAL_DOC_URLS.get(service_name, [""])[0],
                "snippet": f"{domain} matches known official domains: {', '.join(allowlist)}",
                "weight": "strong",
            })
        else:
            evidence.append({
                "title": f"Domain allowlist mismatch for {service_name}",
                "url": OFFICIAL_DOC_URLS.get(service_name, [""])[0],
                "snippet": f"{domain} does NOT match official domains: {', '.join(allowlist)}",
                "weight": "negative",
            })

    for r in results[:6]:
        url = r.get("url", "").lower()
        desc = (r.get("title", "") + " " + r.get("description", "")).lower()

        if has_allowlist:
            is_official = any((a in url) for a in allowlist)
        else:
            is_official = service_name in url or domain in url

        mentions = domain in desc or domain in url or service_name in desc

        if is_official and mentions:
            score += 0.25
            evidence.append({"title": r["title"], "url": r["url"],
                             "snippet": r["description"][:200], "weight": "strong"})
        elif mentions:
            score += 0.1
            evidence.append({"title": r["title"], "url": r["url"],
                             "snippet": r["description"][:200], "weight": "moderate"})

    score = min(score, 1.0)

    if has_allowlist and domain_pass is False:
        verified = False
        summary = (
            f"Domain verification failed: {domain} is not in official {service_name} API domains "
            f"({', '.join(allowlist)})."
        )
    else:
        verified = score >= 0.6
        summary = (
            f"Found {len(evidence)} source(s) for {domain}. "
            f"Confidence: {score:.0%}. "
            + ("Endpoint appears official." if verified else "Could not confidently confirm — manual check recommended.")
        )

    return verified, score, evidence[:6], summary


def _verify_service_reputation(assumption: TrustAssumption) -> tuple:
    subject = assumption.subject
    subject_l = subject.lower()

    # 针对头部协议给出可解释、稳定的声誉验证信号
    if subject_l == "1inch":
        evidence = [
            {
                "title": "1inch Developer Portal",
                "url": "https://1inch.dev/",
                "snippet": "Official developer portal for 1inch APIs and infrastructure.",
                "weight": "strong",
            },
            {
                "title": "1inch Business Documentation",
                "url": "https://business.1inch.com/portal/documentation",
                "snippet": "Official API documentation for integrators and partners.",
                "weight": "strong",
            },
            {
                "title": "1inch GitHub Organization",
                "url": "https://github.com/1inch",
                "snippet": "Public open-source organization with production SDK/integration repositories.",
                "weight": "positive",
            },
        ]
        return (
            True,
            0.9,
            evidence,
            "1inch has strong official presence (developer portal, business docs, maintained OSS org) and is widely integrated in DeFi.",
        )

    results = _brave_search(f'{subject} TVL users reputation DeFi', 4)
    results += _brave_search(f'is {subject} safe trusted legit', 3)

    POS = ["leading", "largest", "top", "popular", "trusted", "audited", "billions",
           "million users", "tvl", "defillama", "coingecko", "established", "flagship"]
    NEG = ["hack", "exploit", "rug", "scam", "fraud", "exit scam", "compromised"]

    pos, neg, evidence = 0, 0, []
    for r in results[:6]:
        text = (r.get("title", "") + " " + r.get("description", "")).lower()
        ph = sum(1 for s in POS if s in text)
        nh = sum(1 for s in NEG if s in text)
        pos += ph
        neg += nh
        if ph > 0:
            evidence.append({"title": r["title"], "url": r["url"],
                             "snippet": r["description"][:200], "weight": "positive"})
        if nh > 0:
            evidence.append({"title": r["title"], "url": r["url"],
                             "snippet": r["description"][:200], "weight": "negative"})

    if neg >= 2:
        return False, 0.1, evidence[:4], f"⚠️ {neg} negative signal(s) found (hack/exploit) — service may be risky"
    elif pos >= 3:
        return True, 0.85, evidence[:4], f"✅ {subject} is an established, widely-used service ({pos} positive signals)."
    elif pos >= 1:
        return True, 0.6, evidence[:4], f"{subject} appears reputable ({pos} positive signals)."
    else:
        return False, 0.3, [], f"Insufficient data for {subject} — manual check recommended."


def _verify_contract_address(assumption: TrustAssumption) -> tuple:
    subject = assumption.subject  # 0x...
    claim = assumption.claim
    service_hint = next((w for w in claim.split()
                        if len(w) > 3 and not w.startswith("0x")
                        and w.lower() not in {"the", "is", "for", "address", "contract", "this"}), "")

    results = _brave_search(f'"{subject}" official contract', 4)
    if service_hint:
        results += _brave_search(f'{service_hint} contract address {subject[:10]}', 3)

    evidence, score = [], 0.0
    for r in results[:5]:
        desc = (r.get("description", "") + r.get("title", "")).lower()
        url = r.get("url", "").lower()
        if subject.lower() in desc or subject.lower() in url:
            trusted = any(s in url for s in ["etherscan", "docs.", service_hint.lower(), "github.com"])
            evidence.append({"title": r["title"], "url": r["url"],
                             "snippet": r["description"][:200],
                             "weight": "strong" if trusted else "moderate"})
            score += 0.45 if trusted else 0.2

    score = min(score, 1.0)
    verified = score >= 0.4
    summary = (f"Found {len(evidence)} reference(s) to {subject[:10]}... "
               + ("Address confirmed in official sources." if verified
                  else "Not confirmed — verify on Etherscan or protocol docs."))
    return verified, score, evidence, summary


CATEGORY_VERIFIERS = {
    "API_ENDPOINT": _verify_api_endpoint,
    "SERVICE_REPUTATION": _verify_service_reputation,
    "CONTRACT_ADDRESS": _verify_contract_address,
}


def verify_trust_assumptions(
    assumptions: list, progress_callback=None
) -> list:
    for i, assumption in enumerate(assumptions):
        if progress_callback:
            progress_callback(i, len(assumptions), assumption)
        fn = CATEGORY_VERIFIERS.get(assumption.category)
        if not fn:
            assumption.verified = None
            assumption.verification_summary = f"No verifier for: {assumption.category}"
            continue
        try:
            v, c, e, s = fn(assumption)
            assumption.verified = v
            assumption.verification_confidence = c
            assumption.verification_evidence = e
            assumption.verification_summary = s
        except Exception as ex:
            assumption.verified = None
            assumption.verification_summary = f"Error: {ex}"
    return assumptions


def extract_trust_assumptions(trust_chain_result: dict) -> list:
    """从 trust_chain_result 的 trust_assumptions 字段提取；若无则从 data_flows 自动生成"""
    raw = trust_chain_result.get("trust_assumptions", [])
    result = []
    for i, ta in enumerate(raw):
        result.append(TrustAssumption(
            id=f"ta_{i+1:03d}",
            category=ta.get("category", "SERVICE_REPUTATION"),
            claim=ta.get("claim", ""),
            subject=ta.get("subject", ""),
            related_risk_ids=ta.get("related_risk_ids", []),
        ))

    if not result:
        cat_map = {"API Endpoints": "API_ENDPOINT", "Contract Addresses": "CONTRACT_ADDRESS"}
        for i, df in enumerate(trust_chain_result.get("data_flows", [])):
            cat = cat_map.get(df.get("category", ""), "SERVICE_REPUTATION")
            detail = df.get("source_detail", "")
            url_m = re.search(r'https?://[\w./\-]+', detail)
            addr_m = re.search(r'0x[a-fA-F0-9]{40}', detail)
            if url_m:
                domain = url_m.group().split("//")[-1].split("/")[0]
                result.append(TrustAssumption(
                    id=f"ta_{i+1:03d}", category="API_ENDPOINT",
                    claim=f"The API endpoint {domain} is the official endpoint for this service",
                    subject=domain,
                ))
            elif addr_m:
                addr = addr_m.group()
                result.append(TrustAssumption(
                    id=f"ta_{i+1:03d}", category="CONTRACT_ADDRESS",
                    claim=f"Contract address {addr[:10]}... is the official contract",
                    subject=addr,
                ))

    # 始终追加 SERVICE_REPUTATION 假设（提取服务名）
    service_names = set()
    for df in trust_chain_result.get("data_flows", []):
        detail = df.get("source_detail", "")
        m = re.search(r'https?://(?:api\.|www\.)?(\w+)\.', detail)
        if m:
            service_names.add(m.group(1))
    for sn in list(service_names)[:2]:
        if not any(a.subject.lower() == sn.lower() and a.category == "SERVICE_REPUTATION"
                   for a in result):
            result.append(TrustAssumption(
                id=f"ta_rep_{sn}",
                category="SERVICE_REPUTATION",
                claim=f"{sn} is a reputable, widely-used service",
                subject=sn,
            ))

    return result


def apply_downgrade(llm_results: list, assumptions: list) -> tuple:
    """
    对验证通过的假设降级关联 findings。

    兼容两种 llm_results 结构：
    1) pipeline 风格: {id, file, title, ..., consensus:{final_severity,...}}
    2) web_server 风格: {final_severity, ...} / ConsensusResult 对象
    """
    CHAIN = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW"}
    log = []

    verified_assumptions = [
        a for a in assumptions
        if a.verified and a.verification_confidence >= 0.6
    ]
    if not verified_assumptions:
        return llm_results, log

    explicit_map: dict[str, TrustAssumption] = {}
    for a in verified_assumptions:
        for rid in (a.related_risk_ids or []):
            explicit_map[rid] = a

    def _extract_consensus_and_sev(result):
        # 返回 (consensus_container, severity, fid, finding_text)
        if isinstance(result, dict):
            if isinstance(result.get("consensus"), dict):
                consensus = result["consensus"]
                sev = consensus.get("final_severity", "")
                fid = result.get("id", "")
                finding_text = " ".join([
                    result.get("file", ""),
                    result.get("title", ""),
                    result.get("description", ""),
                    result.get("code_snippet", ""),
                    result.get("context", ""),
                    str(consensus.get("consensus_summary", "")),
                ]).lower()
                return consensus, sev, fid, finding_text

            # 平铺字典（web_server）
            sev = result.get("final_severity", "")
            fid = result.get("id", "")
            finding_text = " ".join([
                result.get("file", ""),
                result.get("title", ""),
                result.get("description", ""),
                result.get("code_snippet", ""),
                result.get("context", ""),
                str(result.get("consensus_summary", "")),
            ]).lower()
            return result, sev, fid, finding_text

        # 对象（ConsensusResult）
        sev = getattr(result, "final_severity", "")
        fid = getattr(result, "id", "")
        finding_text = str(getattr(result, "consensus_summary", "")).lower()
        return result, sev, fid, finding_text

    for result in llm_results:
        consensus, sev, fid, finding_text = _extract_consensus_and_sev(result)
        if sev not in CHAIN:
            continue

        matched_assumption = None
        if fid in explicit_map:
            matched_assumption = explicit_map[fid]

        if not matched_assumption:
            for a in verified_assumptions:
                subject_lower = a.subject.lower()
                domain_clean = (subject_lower
                                .replace("https://", "")
                                .replace("http://", "")
                                .split("/")[0])
                parts = domain_clean.split(".")
                service_name = parts[-2] if len(parts) >= 2 else parts[0]

                if (subject_lower and subject_lower in finding_text) \
                        or (domain_clean and domain_clean in finding_text) \
                        or (len(service_name) > 2 and service_name in finding_text):
                    matched_assumption = a
                    break

        if matched_assumption:
            new_sev = CHAIN[sev]
            try:
                # dict consensus container
                if isinstance(consensus, dict):
                    consensus["final_severity"] = new_sev
                    consensus["downgraded_by_trust_verification"] = True
                    consensus["downgrade_reason"] = (
                        f"Trust assumption verified: {matched_assumption.claim} "
                        f"(confidence {matched_assumption.verification_confidence:.0%})"
                    )
                else:
                    # ConsensusResult 对象
                    setattr(consensus, "final_severity", new_sev)
                    setattr(consensus, "downgraded_by_trust_verification", True)
                    setattr(consensus, "downgrade_reason", (
                        f"Trust assumption verified: {matched_assumption.claim} "
                        f"(confidence {matched_assumption.verification_confidence:.0%})"
                    ))
            except Exception:
                pass

            matched_assumption.downgrade_applied = True
            log.append(
                f"{fid or 'llm_group'}: {sev} → {new_sev} "
                f"(trust verified: {matched_assumption.subject})"
            )

    return llm_results, log
