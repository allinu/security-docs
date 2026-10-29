#!/usr/bin/env python3
"""采集管道：NVD → KEV → EPSS → Exploit-DB / Metasploit / Nuclei → GitHub 仓库。

每个阶段都可单独调用，且带缓存（已存在的日文件直接复用），
便于定时任务失败后从断点重试。
"""
import csv
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import DATA, age_days, dump, load, path, window_for  # noqa: E402

UA = "Mozilla/5.0 (compatible; vuln-daily-docs/1.0)"


def curl(url, timeout=120, headers=None, out=None, data=None):
    cmd = ["curl", "-sL", "-m", str(timeout), "-A", UA]
    for h in headers or []:
        cmd += ["-H", h]
    if data:
        cmd += ["-d", data]
    if out:
        cmd += ["-o", out]
    cmd.append(url)
    p = subprocess.run(cmd, capture_output=True)
    return p.stdout


def curl_json(url, timeout=120, headers=None, tries=3):
    for i in range(tries):
        raw = curl(url, timeout=timeout, headers=headers)
        try:
            d = json.loads(raw)
            return d
        except Exception:
            time.sleep(5 * (i + 1))
    return None


# ---------------------------------------------------------------- NVD
def fetch_nvd(day, force=False):
    """抓取单日窗口的 NVD 全量条目（分页）"""
    fp = path("nvd", f"{day}.json")
    if os.path.exists(fp) and not force:
        d = load(fp)
        print(f"[nvd] {day} cached {d['total']}", flush=True)
        return d
    s, e = window_for(day)
    allv, start, guard = [], 0, 0
    while True:
        url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?pubStartDate={s}&pubEndDate={e}&resultsPerPage=2000&startIndex={start}")
        d = curl_json(url, timeout=180)
        guard += 1
        if d is None or "vulnerabilities" not in d:
            raise RuntimeError(f"NVD 抓取失败：{day} startIndex={start}（已重试 3 次）")
        vs = d.get("vulnerabilities", [])
        allv.extend(vs)
        start += len(vs)
        if start >= d.get("totalResults", 0) or not vs or guard > 12:
            break
        time.sleep(7)
    out = {"day": day, "window": [s, e], "total": len(allv), "items": allv}
    dump(out, fp)
    print(f"[nvd] {day} fetched {len(allv)}", flush=True)
    return out


# ---------------------------------------------------------------- KEV
def fetch_kev(force=False, max_age=0.4):
    fp = path("kev.json")
    if not force and age_days(fp) < max_age:
        return load(fp)
    raw = curl("https://www.cisa.gov/sites/default/files/feeds/"
               "known_exploited_vulnerabilities.json", timeout=90)
    d = json.loads(raw)
    dump(d, fp)
    print(f"[kev] catalog {d['catalogVersion']} count={d['count']}", flush=True)
    return d


# ---------------------------------------------------------------- 基线索引
def ensure_msf(max_age=7, force=False):
    fp = path("msf_index.json")
    if not force and age_days(fp) < max_age:
        return load(fp, {})
    src = path("msf.json")
    if force or age_days(src) > max_age:
        # raw.githubusercontent 常见超时，改走 jsDelivr CDN
        raw = curl("https://cdn.jsdelivr.net/gh/rapid7/metasploit-framework@master/"
                   "db/modules_metadata_base.json", timeout=300)
        if len(raw) < 10 ** 6:
            raise RuntimeError("Metasploit 元数据下载失败")
        open(src, "wb").write(raw)
    msf = json.load(open(src, encoding="utf-8"))
    idx = {}
    for name, m in msf.items():
        for r in (m.get("references") or []):
            mm = re.match(r"CVE-(\d{4}-\d+)$", str(r))
            if mm:
                idx.setdefault("CVE-" + mm.group(1), []).append({
                    "name": name, "type": m.get("type"),
                    "platform": m.get("platform"), "name_h": m.get("name"),
                    "disclosure": m.get("disclosure_date")})
    dump(idx, fp)
    print(f"[msf] index keys={len(idx)}", flush=True)
    return idx


def ensure_edb(max_age=7, force=False):
    fp = path("edb_index.json")
    if not force and age_days(fp) < max_age:
        return load(fp, {})
    src = path("edb.csv")
    if force or age_days(src) > max_age:
        raw = curl("https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
                   "files_exploits.csv", timeout=300)
        if len(raw) < 10 ** 6:
            raise RuntimeError("Exploit-DB 清单下载失败")
        open(src, "wb").write(raw)
    idx = {}
    with open(src, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            for mm in re.finditer(r"CVE-(\d{4}-\d+)", row.get("codes") or ""):
                idx.setdefault("CVE-" + mm.group(1), []).append({
                    "id": row.get("id"), "file": row.get("file"),
                    "desc": row.get("description"), "date": row.get("date_published"),
                    "author": row.get("author"), "type": row.get("type"),
                    "platform": row.get("platform")})
    dump(idx, fp)
    print(f"[edb] index keys={len(idx)}", flush=True)
    return idx


def ensure_nuclei(max_age=7, force=False):
    """用 GitHub trees API 取模板全量清单做精确匹配，避免逐条 HEAD 探测"""
    fp = path("nuclei_map.json")
    if not force and age_days(fp) < max_age:
        return load(fp, {})
    d = curl_json("https://api.github.com/repos/projectdiscovery/nuclei-templates/"
                  "git/trees/main?recursive=1", timeout=180)
    if not d or "tree" not in d:
        if os.path.exists(fp):
            print("[nuclei] 刷新失败，沿用旧索引", flush=True)
            return load(fp, {})
        return {}
    if d.get("truncated"):
        print("[nuclei] 警告：tree 响应被截断，模板覆盖可能不全", flush=True)
    m = {}
    for e in d["tree"]:
        p = e.get("path", "")
        if p.endswith(".yaml") and "/cves/" in p and "CVE-" in p:
            name = os.path.basename(p).replace(".yaml", "").split("_")[0]
            if name.startswith("CVE-"):
                m.setdefault(name, p)
    dump(m, fp)
    print(f"[nuclei] templates={len(m)}", flush=True)
    return m


# ---------------------------------------------------------------- 标准化
def _cvss(cve):
    m = cve.get("metrics", {})
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                     ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        if m.get(key):
            item = m[key][0]
            cd = item.get("cvssData", {})
            return {"score": cd.get("baseScore"), "vector": cd.get("vectorString"),
                    "severity": cd.get("baseSeverity") or item.get("baseSeverity"),
                    "version": ver, "source": item.get("source")}
    return {"score": None, "vector": None, "severity": None, "version": None, "source": None}


def _cwe(cve):
    out = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in out:
                out.append(v)
    return out


def _cpe(cve):
    vs, ps = [], []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                p = (cm.get("criteria") or "").split(":")
                if len(p) > 4:
                    if p[3] not in vs:
                        vs.append(p[3])
                    if p[4] not in ps:
                        ps.append(p[4])
    return vs[:6], ps[:6]


def _refs(cve, tags=None):
    out = []
    for r in cve.get("references", []):
        t = r.get("tags") or []
        if tags and not (set(t) & set(tags)):
            continue
        out.append({"url": r.get("url"), "tags": t})
    return out


def epss_batch(ids):
    out = {}
    ids = [i for i in ids if i.startswith("CVE-")]
    for i in range(0, len(ids), 50):
        url = "https://api.first.org/data/v1/epss?cve=" + ",".join(ids[i:i + 50])
        raw = curl(url, timeout=45)
        try:
            for r in json.loads(raw).get("data", []):
                out[r["cve"]] = {"epss": float(r["epss"]), "pct": float(r["percentile"]),
                                 "date": r["date"]}
        except Exception:
            pass
        time.sleep(1)
    return out


def rank_score(it, ep):
    s = (it["cvss"]["score"] or 0)
    s += 3.0 if it["kev"] else 0
    s += 0.6 if it["msf"] else 0
    s += 0.5 if it["edb"] else 0
    s += 2.5 * (ep or {}).get("epss", 0)
    v = it["cvss"]["vector"] or ""
    if "PR:N" in v:
        s += 0.4
    if "AV:N" in v:
        s += 0.2
    return round(s, 2)


def build_base(day, force=False):
    """标准化 + 合并 KEV/EPSS/Msf/EDB/Nuclei，输出 base/{day}.json"""
    fp = path("base", f"{day}.json")
    if os.path.exists(fp) and not force:
        b = load(fp)
        print(f"[base] {day} cached {b['total']}", flush=True)
        return b

    raw = load(path("nvd", f"{day}.json"))
    if not raw:
        raise RuntimeError(f"缺少 NVD 数据：{day}")
    kev = {v["cveID"]: v for v in (fetch_kev() or {}).get("vulnerabilities", [])}
    msf = ensure_msf()
    edb = ensure_edb()
    nuclei = ensure_nuclei()

    items = []
    for it in raw["items"]:
        c = it["cve"]
        if c.get("vulnStatus") == "Rejected":
            continue
        cv = _cvss(c)
        vs, ps = _cpe(c)
        cid = c["id"]
        k = kev.get(cid)
        items.append({
            "id": cid, "published": c.get("published"), "modified": c.get("lastModified"),
            "status": c.get("vulnStatus"),
            "desc": (c.get("descriptions") or [{}])[0].get("value", ""),
            "cvss": cv, "cwe": _cwe(c), "vendors": vs, "products": ps,
            "kev": bool(k), "kev_due": (k or {}).get("dueDate"),
            "kev_ransom": (k or {}).get("knownRansomwareCampaignUse"),
            "kev_name": (k or {}).get("vulnerabilityName"),
            "kev_date": (k or {}).get("dateAdded"),
            "msf": msf.get(cid, []), "edb": edb.get(cid, []),
            "refs": [r["url"] for r in _refs(c)][:8],
            "advisories": [r["url"] for r in _refs(c, ["Vendor Advisory", "Third Party Advisory"])][:4],
            "patch": [r["url"] for r in _refs(c, ["Patch"])][:3],
            "poc_ref": [u for u in [r["url"] for r in c.get("references", [])
                                    if set(r.get("tags") or []) & {"Exploit"}
                                    or "poc" in (r.get("url") or "").lower()]
                        if "security/advisories" not in u and "/commit/" not in u
                        and "vuldb.com" not in u][:3],
            "nuclei": ({"path": nuclei[cid],
                        "url": f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{nuclei[cid]}"}
                       if cid in nuclei else None),
        })

    # 外部情报源（可选增强）：不可达时 ext=None，全链路静默降级
    try:
        import extsrc
        ext_idx, ext_meta = extsrc.fetch()
    except Exception as exc:  # noqa: BLE001
        print(f"[extsrc] 跳过来源：{exc}", flush=True)
        ext_idx, ext_meta = None, {}
    for it in items:
        it["ext"] = (ext_idx or {}).get(it["id"])

    pre = sorted(items, key=lambda x: -(x["cvss"]["score"] or 0) - (3 if x["kev"] else 0))
    ep = epss_batch([i["id"] for i in pre[:160]])
    for it in items:
        it["epss"] = ep.get(it["id"])
        it["score"] = rank_score(it, ep.get(it["id"]))

    items.sort(key=lambda x: -x["score"])
    out = {"day": day, "window": raw["window"], "total": len(items), "items": items,
           "ext_meta": ext_meta}
    dump(out, fp)
    n_poc = sum(1 for i in items if i["nuclei"] or i["msf"] or i["edb"])
    print(f"[base] {day} total={len(items)} epss={sum(1 for i in items if i['epss'])} "
          f"prebuilt_poc={n_poc}", flush=True)
    return out


# ---------------------------------------------------------------- GitHub PoC
def _gh_headers():
    h = ["Accept: application/vnd.github+json"]
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        h.append(f"Authorization: Bearer {tok}")
    return h


def gh_search(cid):
    q = urllib.parse.quote(cid)
    d = curl_json(f"https://api.github.com/search/repositories?q={q}"
                  f"&sort=updated&order=desc&per_page=10",
                  timeout=45, headers=_gh_headers(), tries=2)
    if not d or "items" not in d:
        return {"error": (d or {}).get("message", "request failed")}
    return {"total": d.get("total_count", 0), "repos": [{
        "full_name": i["full_name"], "stars": i["stargazers_count"],
        "created": i["created_at"], "pushed": i["pushed_at"],
        "desc": (i.get("description") or "")[:180], "url": i["html_url"],
        "lang": i.get("language"), "fork": i.get("fork")} for i in d["items"]]}


def gh_poc(day, per_day=12, force=False):
    """对未命中 Nuclei/MSF/EDB 的高危条目做仓库级检索（未认证限额 10 次/分钟）"""
    fp = path("gh", f"{day}.json")
    done = {} if force else (load(fp, {}) or {})
    base = load(path("base", f"{day}.json"))
    if not base:
        return done
    cands = []
    for it in base["items"]:
        if it["id"] in done:
            continue
        if it["msf"] or it["edb"] or it.get("nuclei"):
            continue
        if (it["cvss"]["score"] or 0) < 7.0:
            continue
        cands.append(it)
    # 优先检索评分高的（含 KEV、EPSS 高值）
    cands.sort(key=lambda x: -x["score"])
    sleep_s = 6.5 if (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")) else 7.5
    for it in cands[:per_day]:
        res = gh_search(it["id"])
        if "error" in res and "rate limit" in str(res["error"]).lower():
            # 未认证限额 10 次/分钟：等一分钟后重试同一编号，避免静默丢失结果
            print(f"[gh] 触发限速，等待 65 秒后重试 {it['id']}", flush=True)
            time.sleep(65)
            res = gh_search(it["id"])
        if "error" in res:
            print(f"[gh] {it['id']} ERR {res['error']}", flush=True)
            continue
        done[it["id"]] = res
        dump(done, fp)
        print(f"[gh] {it['id']} repos={res['total']}", flush=True)
        time.sleep(sleep_s)
    hits = sum(1 for v in done.values() if v.get("total"))
    print(f"[gh] {day} checked={len(done)} hits={hits}", flush=True)
    return done


def collect(day, per_day=12, force=False):
    """完整采集链"""
    fetch_nvd(day, force=force)
    fetch_kev(force=force)
    build_base(day, force=force or True)
    gh_poc(day, per_day=per_day, force=False)
    return load(path("base", f"{day}.json"))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "collect"
    day = sys.argv[2] if len(sys.argv) > 2 else __import__("common").today_cst()
    if cmd == "collect":
        collect(day)
    elif cmd == "nvd":
        fetch_nvd(day, force="--force" in sys.argv)
    elif cmd == "base":
        build_base(day, force="--force" in sys.argv)
    elif cmd == "gh":
        gh_poc(day)
    else:
        print(__doc__)
