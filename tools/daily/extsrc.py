#!/usr/bin/env python3
"""外部情报源：http://3.25.211.44:8080/report.html（多源漏洞情报汇总）。

该页是静态快照，表格行结构固定：
  # | CVE | 标题 | CVSS(+版本) | 等级 | EPSS% | KEV | PoC 来源标签 | 更新时间

这里把它解析成 {cve: {...}} 索引，用于：
1. 交叉校验本窗口条目的 PoC 状态（对方聚合了 GitHub/Nuclei/EDB/MSF 的结果）；
2. 找出“对方标了 PoC、我们四源未命中”的编号，提醒补查。
页面不可达时返回 None，调用方应静默降级（该源为可选增强）。
"""
import json
import re
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from common import age_days, dump, load, path  # noqa: E402
import pipeline  # noqa: E402

URL = "http://3.25.211.44:8080/report.html"
ROW_RE = re.compile(r'<tr[^>]*>([\s\S]{0,3000}?)</tr>')
CVE_RE = re.compile(r'(CVE-\d{4}-\d{4,})')
TAG_RE = re.compile(r'<span class="tag ([^"]*)"[^>]*>([^<]*)</span>')
POC_FLAG = re.compile(r'<span class="poc-flag">([^<]*)</span>')
TITLE_RE = re.compile(r'<a href="#" class="vlink"[^>]*>([^<]*)</a>')
NUM_RE = re.compile(r'<td class="num">\s*([0-9.]+)')


def _cells(row):
    return re.findall(r'<td[^>]*>([\s\S]*?)</td>', row)


def parse(html):
    """返回 (index, meta)"""
    meta = {}
    m = re.search(r'生成时间\s*([0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2})', html)
    if m:
        meta["generated_at"] = m.group(1).strip()
    totals = re.findall(r'<div class="n">([0-9,]+)</div>\s*<div class="l">([^<]+)</div>', html)
    if totals:
        meta["totals"] = {k.strip(): int(v.replace(",", "")) for v, k in totals}

    idx = {}
    for row in ROW_RE.findall(html):
        m = CVE_RE.search(row)
        if not m:
            continue
        cid = m.group(1)
        cells = _cells(row)
        if len(cells) < 7:
            continue
        rec = {"title": "", "cvss": None, "sev": None, "epss": None,
               "kev": False, "poc": [], "updated": None}
        t = TITLE_RE.search(row)
        if t:
            rec["title"] = re.sub(r"\s+", " ", t.group(1)).strip()
        nm = NUM_RE.search(row)
        if nm:
            try:
                rec["cvss"] = float(nm.group(1))
            except ValueError:
                pass
        for cls, text in TAG_RE.findall(row):
            text = text.strip()
            if cls.startswith("t-kev"):
                rec["kev"] = True
            elif cls.startswith(("t-gh", "t-nuc", "t-edb", "t-msf", "t-poc", "t-exp")):
                rec["poc"].append(text)
            elif cls.startswith(("t-crit", "t-high", "t-mid", "t-low")):
                rec["sev"] = text
        if POC_FLAG.search(row):
            rec["poc"].append("PoC")
        pct = re.search(r'>\s*([0-9.]+)%\s*<div class="bar"', row)
        if pct:
            rec["epss"] = float(pct.group(1)) / 100.0
        dt = re.search(r'<td class="num dim">(\d{4}-\d{2}-\d{2})', row)
        if dt:
            rec["updated"] = dt.group(1)
        rec["poc"] = sorted(set(rec["poc"]))
        # 同一 CVE 可能出现在多个筛选区块，保留信息更全的一条
        old = idx.get(cid)
        if old is None or len(rec["poc"]) > len(old["poc"]) or (
                rec["epss"] and not old["epss"]):
            idx[cid] = rec
    meta["cve_count"] = len(idx)
    meta["poc_count"] = sum(1 for v in idx.values() if v["poc"])
    return idx, meta


def fetch(max_age=0.4, force=False):
    """抓取并解析；失败时回落到缓存。返回 (index, meta) 或 (None, {})"""
    fp = path("extsrc.json")
    cached = load(fp)
    if not force and age_days(fp) < max_age and cached:
        return cached.get("index", {}), cached.get("meta", {})
    raw = pipeline.curl(URL, timeout=40)
    if not raw or b"<html" not in raw[:2000].lower():
        print("[extsrc] 页面不可达，沿用缓存（若有）", flush=True)
        if cached:
            return cached.get("index", {}), cached.get("meta", {})
        return None, {}
    html = raw.decode("utf-8", "replace")
    idx, meta = parse(html)
    if not idx:
        print("[extsrc] 解析结果为空，可能页面结构已变；沿用缓存", flush=True)
        if cached:
            return cached.get("index", {}), cached.get("meta", {})
        return None, {}
    meta["fetched_at"] = time.strftime("%Y-%m-%d %H:%M")
    meta["url"] = URL
    dump({"index": idx, "meta": meta}, fp)
    print(f"[extsrc] cve={len(idx)} poc={meta['poc_count']} "
          f"generated_at={meta.get('generated_at', '?')}", flush=True)
    return idx, meta


if __name__ == "__main__":
    idx, meta = fetch(force=True)
    print(json.dumps(meta, ensure_ascii=False, indent=1))
    for k in list(idx)[:3]:
        print(k, idx[k])
