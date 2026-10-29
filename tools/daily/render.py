#!/usr/bin/env python3
"""渲染单日 Markdown"""
import json, os, sys, datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import DATA as D
from gen import (CWE_MAP, UNKNOWN_PROD, sev_of, vtype, poc_of, priority, cond_table,
                 attack_chain, fofa, epss_txt, kev_txt, guess_product)

def _load_kev():
    fp = f"{D}/kev.json"
    if os.path.exists(fp):
        return json.load(open(fp, encoding="utf-8"))
    return {"count": 0, "catalogVersion": "unavailable", "vulnerabilities": []}


KEV_CAT = _load_kev()
KEV_ALL = {v["cveID"]: v for v in KEV_CAT["vulnerabilities"]}


def _refresh_kev():
    """在渲染前重读 KEV 目录。

    模块导入时采集阶段尚未运行，此时读到的是上一轮缓存的旧目录，
    会导致正文累计数与 catalogVersion 滞后一天；渲染前必须重新加载。
    """
    global KEV_CAT, KEV_ALL
    KEV_CAT = _load_kev()
    KEV_ALL = {v["cveID"]: v for v in KEV_CAT["vulnerabilities"]}


def kev_today(day):
    return [v for v in KEV_CAT["vulnerabilities"] if v["dateAdded"] == day]


def load(p, default=None):
    return json.load(open(p)) if os.path.exists(p) else default


def pct(a, b):
    return f"{a / b * 100:.1f}%" if b else "0%"


def pretty(x):
    if not x:
        return ""
    t = x.replace("_", " ").replace("-", " ").strip()
    return " ".join(w.capitalize() if w.islower() else w for w in t.split())


def clean(s):
    return (s or "").replace("|", "\\|").replace("\n", " ").strip()


def detail_section(n, it, gh, nar, day=None):
    cid = it["id"]
    cv = it["cvss"]
    sev = sev_of(cv["score"])
    poc, srcs = poc_of(it, gh)
    p = priority(it, poc, gh)
    net, auth, ui, ac = cond_table(it)
    dn = nar.get("detail", {}).get(cid, {})
    o = []
    a = o.append
    a(f"### 3.{n} {cid} — {dn.get('title') or (clean(it['desc'])[:60] + '…')}")
    a("")
    a(f'!!! {"danger" if sev in ("严重", "高危") else "warning"} "{sev}漏洞（{dn.get("tag") or vtype(it)}，CVSS {cv["score"]}）"')
    a(f"    {dn.get('oneline') or clean(it['desc'])[:180]}")
    a("")
    # 3.N.1
    a(f"#### 3.{n}.1 基本信息")
    a("")
    a("| 字段 | 内容 |")
    a("| --- | --- |")
    a(f"| **CVE编号** | `{cid}` |")
    a(f"| **CWE编号** | {'、'.join('`' + c + '`' for c in it['cwe'][:3]) or '未标注'} |")
    a(f"| **漏洞名称** | {dn.get('title') or vtype(it)} |")
    a(f"| **漏洞类型** | {dn.get('vtype') or vtype(it)} |")
    a(f"| **风险等级** | {sev} |")
    src = cv.get("source") or "—"
    if len(src) == 36 and src.count("-") == 4:
        src = "CNA（未具名来源）"
    a(f"| **CVSS评分** | {cv['score']}（CVSS {cv['version']}，评分方 {src}） |")
    a(f"| **CVSS向量** | `{cv['vector'] or '—'}` |")
    a(f"| **EPSS评分** | {epss_txt(it)} |")
    a(f"| **披露日期** | {it['published'][:10]} |")
    a(f"| **更新日期** | {it['modified'][:10]} |")
    a(f"| **CISA KEV** | {kev_txt(it, day)} |")
    a(f"| **在野利用** | {'已确认（KEV 收录）' if it['kev'] else '未发现公开报道'} |")
    a(f"| **PoC状态** | {poc}{'（' + '、'.join(srcs) + '）' if srcs else ''} |")
    if it["patch"]:
        fixst = "已发布官方补丁／修复版本"
    elif it["advisories"]:
        fixst = "厂商已发布公告（含修复版本）"
    elif it["refs"]:
        fixst = "厂商公告已披露，修复版本待确认"
    else:
        fixst = "暂无官方信息"
    a(f"| **补丁状态** | {fixst} |")
    a(f"| **信息可信度** | {'高' if it['kev'] or it['patch'] or it['advisories'] or len(it['refs']) >= 2 else '中'} |")
    a("")
    # 3.N.2
    a(f"#### 3.{n}.2 漏洞摘要")
    a("")
    a(dn.get("summary") or clean(it["desc"]))
    a("")
    a("> 原文摘要（NVD）：" + clean(it["desc"])[:700])
    a("")
    # 3.N.3
    a(f"#### 3.{n}.3 影响产品与版本")
    a("")
    a("| 厂商 | 产品/组件 | 受影响版本 | 修复版本 | 部署形态 |")
    a("|---|---|---|---|---|")
    vends = ([dn["vendor"]] if dn.get("vendor") else []) + [pretty(v) for v in it["vendors"][:2]]
    prods = ([dn["product"]] if dn.get("product") else []) + [pretty(v) for v in it["products"][:2]]
    if not prods:
        g = guess_product(it["desc"])
        prods = [g] if g else ["见公告"]
    if not vends:
        vends = ["见公告"]
    fix = dn.get("fixver") or "见厂商公告"
    aff = dn.get("affected") or "见厂商公告"
    a(f"| {', '.join(vends)} | {', '.join(prods)} | `{aff}` | `{fix}` | {dn.get('deploy') or '本地部署/自建'} |")
    a("")
    a('!!! warning "版本说明"')
    a("    版本范围以厂商官方安全公告为准；NVD 配置节点（CPE）仅反映已确认的产品范围，未列出的版本不排除受影响。")
    a("")
    # 3.N.4
    a(f"#### 3.{n}.4 漏洞分类")
    a("")
    a("| 分类体系 | 编号 | 名称 |")
    a("| --- | --- | --- |")
    for c in it["cwe"][:3]:
        name, owasp, capec = CWE_MAP.get(c, ("未映射", "—", "—"))
        a(f"| CWE | `{c}` | {name} |")
        a(f"| OWASP Top 10 | `{owasp.split(' ')[0]}` | {owasp} |")
        a(f"| CAPEC | `{capec}` | 攻击模式参考 |")
    if not it["cwe"]:
        a("| CWE | `—` | NVD 未标注 |")
    a("")
    # 3.N.5
    a(f"#### 3.{n}.5 利用条件与技术原理")
    a("")
    a("| 条件 | 状态 | 说明 |")
    a("| --- | --- | --- |")
    a(f"| 网络可达 | {net} | {dn.get('access') or '通过 CVSS 向量推断的访问路径'} |")
    a(f"| 身份认证 | {auth} | {'无需任何凭据即可触发' if auth == '无需' else '需相应账号权限'} |")
    a(f"| 用户交互 | {ui} | {'无需受害者交互' if ui == '不需要' else '需受害者参与'} |")
    a(f"| 特定配置 | {dn.get('config') or '否'} | {dn.get('config_note') or '默认配置下即可能受影响'} |")
    a(f"| 利用复杂度 | {ac} | {dn.get('complex') or '按 CVSS 攻击复杂度字段判断'} |")
    a("")
    a("**技术原理：**")
    a("")
    a(dn.get("principle") or "见上文漏洞摘要与 NVD 原文描述。")
    a("")
    if dn.get("chain", True):
        it_chain = dict(it)
        it_chain["vendors"] = [v for v in vends if v != "NVD 未标注"] or ["目标厂商"]
        it_chain["products"] = [x for x in prods if x not in ("见公告", UNKNOWN_PROD)] or ["目标组件"]
        a("**核心利用链：**")
        a("")
        a("```text")
        a(attack_chain(it_chain))
        a("```")
        a("")
    # 3.N.6 PoC
    a(f"#### 3.{n}.6 PoC 与利用情况（多源核验）")
    a("")
    a("| 数据源 | 结果 | 详情 |")
    a("| --- | --- | --- |")
    a(f"| Nuclei 模板 | {'命中' if it.get('nuclei') else '未命中'} | {('`' + it['nuclei']['path'] + '`') if it.get('nuclei') else 'nuclei-templates 年内目录未检出同名模板'} |")
    if it["msf"]:
        m = it["msf"][0]
        a(f"| Metasploit | 命中 {len(it['msf'])} 个模块 | `{m['name']}`（{m.get('type')}/{m.get('platform')}） |")
    else:
        a("| Metasploit | 未命中 | 官方模块库 references 中无该编号 |")
    if it["edb"]:
        e = it["edb"][0]
        a(f"| Exploit-DB | 命中 {len(it['edb'])} 条 | EDB-{e['id']} `{clean(e['desc'])[:60]}`（{e['date']}） |")
    else:
        a("| Exploit-DB | 未命中 | files_exploits.csv 中无该编号关联条目 |")
    g = (gh or {}).get(cid) or {}
    if g.get("total"):
        a(f"| GitHub 仓库 | 命中 {g['total']} 个 | " + "；".join(
            f"`{r['full_name']}`（★{r['stars']}，{r['created'][:10]}）" for r in g["repos"][:3]) + " |")
    elif g:
        a("| GitHub 仓库 | 未命中 | 仓库检索 `q=" + cid + "` 返回 0 条 |")
    else:
        a("| GitHub 仓库 | 未检索 | 本期未纳入 GitHub 检索配额 |")
    a(f"| 公告引用 | {'有' if it['poc_ref'] else '无'} | {', '.join(it['poc_ref'][:2]) if it['poc_ref'] else 'NVD 引用中无 Exploit 标签链接'} |")
    e = it.get("ext")
    if e:
        tag = "、".join(e.get("poc") or []) or "对方未标记 PoC"
        a(f"| 外部情报源 | {'命中' if e.get('poc') else '未命中'} | {tag}"
          f"（该源 CVSS {e.get('cvss') or '—'}／EPSS "
          f"{(str(round(e['epss'] * 100, 1)) + '%') if e.get('epss') is not None else '—'}，"
          f"更新于 {e.get('updated') or '—'}） |")
    else:
        a("| 外部情报源 | 未覆盖 | 该源本次快照未包含此编号（或页面不可达） |")
    a("")
    if g.get("repos"):
        a("**已发现的公开 PoC 仓库：**")
        a("")
        a("| 仓库 | Stars | 创建时间 | 最近推送 | 语言 | 说明 |")
        a("| --- | ---: | --- | --- | --- | --- |")
        for r in g["repos"][:5]:
            a(f"| [`{r['full_name']}`]({r['url']}) | {r['stars']} | {r['created'][:10]} | {r['pushed'][:10]} | {r.get('lang') or '—'} | {clean(r['desc'])[:80] or '—'} |")
        a("")
    a('!!! warning "使用边界"')
    a("    以上 PoC/检测模板仅可用于自有资产或已获书面授权的评估场景。生产环境验证建议优先使用 Nuclei 模板的 `-dry-run` 或版本比对方式，避免触发破坏性分支。")
    a("")
    # 3.N.7 暴露面
    a(f"#### 3.{n}.7 暴露面与资产检索")
    a("")
    kw = (dn.get("kw") or (prods[0] if prods[0] != "见公告" else "")
          or (pretty(it["vendors"][0]) if it["vendors"] else "")
          or "（需人工确认产品名）")
    a("| 类型 | 检索特征 |")
    a("| --- | --- |")
    if kw.startswith("（需人工确认"):
        a("| 产品关键字 | —（NVD 未提供 CPE，需按公告确认产品名后再检索） |")
        for k in ("FOFA", "Hunter", "Shodan", "ZoomEye"):
            a(f"| {k} | — |")
    else:
        a(f"| 产品关键字 | `{kw}` |")
        a(f"| FOFA | `body=\"{kw}\"` / `app=\"{kw.split(' ')[0]}\"` |")
        a(f"| Hunter | `web.body=\"{kw}\"` |")
        a(f"| Shodan | `http.html:\"{kw.split(' ')[0]}\"` |")
        a(f"| ZoomEye | `app:\"{kw.split(' ')[0]}\"` |")
    a(f"| 默认端口 | {dn.get('ports') or '按产品默认端口'} |")
    a("")
    a("> 空间测绘结果仅作资产发现线索，需进一步人工确认版本后再判定是否受影响。")
    a("")
    # 3.N.8 检测
    a(f"#### 3.{n}.8 检测与排查")
    a("")
    a("| 检测项 | 可疑特征 |")
    a("| --- | --- |")
    a(f"| 请求路径 | {dn.get('detect_path') or '与漏洞组件相关的接口路径'} |")
    a(f"| 请求方法 | {dn.get('detect_method') or 'GET/POST'} |")
    a(f"| 参数特征 | {dn.get('detect_param') or '异常长度、编码或含 ../ :: %00 等序列'} |")
    a(f"| 响应状态 | {dn.get('detect_status') or '异常 200/500 组合或非预期内容回显'} |")
    a("| 进程行为 | Web 服务拉起 `sh`/`bash`/`cmd`/`powershell`/`curl`/`wget` |")
    a("| 文件行为 | Web 目录、临时目录出现新增脚本或 webshell |")
    a("| 网络行为 | 异常 DNS 解析、反向连接、数据外传 |")
    a("")
    a("排查顺序建议：资产版本确认 → 暴露面收敛 → 日志回溯（WAF/访问日志/EDR）→ 主机侧异常进程与文件 → 异常外联。")
    a("")
    # 3.N.9 处置优先级
    a(f"#### 3.{n}.9 处置优先级")
    a("")
    a("| 研判维度 | 状态 |")
    a("| --- | --- |")
    a(f"| 互联网暴露 | {'是' if net == '是' else '视部署'} |")
    a(f"| 无需认证利用 | {'是' if auth == '无需' else '否'} |")
    a(f"| 利用复杂度低 | {'是' if ac == '低' else '否'} |")
    a(f"| 已公开 PoC | {'是' if poc == '已公开' else '否'} |")
    a(f"| 已确认在野利用 | {'是' if it['kev'] else '否'} |")
    a(f"| 已纳入 CISA KEV | {'是' if it['kev'] else '否'} |")
    a(f"| EPSS 高于 50% | {'是' if (it.get('epss') or {}).get('epss', 0) > 0.5 else '否'} |")
    a("")
    a(f'!!! danger "综合处置优先级：{p}"')
    a(f"    - **P0**：紧急处置，已在野利用或直接影响核心互联网资产；")
    a(f"    - **P1**：24 小时内处置，PoC 公开或利用门槛低；")
    a(f"    - **P2**：3 个工作日内处置，利用条件受限；")
    a(f"    - **P3**：常规整改，风险较低或仅影响非关键场景。")
    a(f"    本期判定：**{p}**（评分 = CVSS {cv['score']} + KEV {int(it['kev'])} + PoC {int(poc == '已公开')} + EPSS {round((it.get('epss') or {}).get('epss', 0), 2)}）")
    a("")
    # 3.N.10 修复
    a(f"#### 3.{n}.10 修复与缓解措施")
    a("")
    a("**官方修复：**")
    a("")
    for i, s in enumerate(dn.get("fixsteps") or [
        f"升级至厂商公告给出的安全版本（{fix}）",
        "升级前备份配置与业务数据，并在测试环境验证兼容性",
        "升级后复核版本号与补丁状态，重新执行检测验证",
    ], 1):
        a(f"{i}. {s}")
    if it["patch"] or it["advisories"]:
        a("")
        a("补丁与公告链接：")
        for u in (it["patch"] + it["advisories"])[:3]:
            a(f"- {u}")
    a("")
    a("**临时缓解：**")
    a("")
    for s in (dn.get("mitigation") or [
        "限制受影响接口/端口的互联网访问，仅允许可信源 IP",
        "在 WAF/IPS 上针对该漏洞特征增加拦截规则",
        "关闭非必要的相关功能模块，降低攻击面",
    ]):
        a(f"- {s}")
    a("")
    # 3.N.11 参考
    a(f"#### 3.{n}.11 参考资料")
    a("")
    refs = [f"- NVD：https://nvd.nist.gov/vuln/detail/{cid}",
            f"- CVE 官方记录：https://www.cve.org/CVERecord?id={cid}"]
    if it["kev"]:
        refs.append(f"- CISA KEV：https://www.cisa.gov/known-exploited-vulnerabilities-catalog（{cid}）")
    refs.append(f"- FIRST EPSS：https://api.first.org/data/v1/epss?cve={cid}")
    for u in (it["advisories"] + it["patch"] + it["refs"])[:4]:
        if u not in refs:
            refs.append(f"- 公告/参考：{u}")
    if it.get("nuclei"):
        refs.append(f"- Nuclei 模板：{it['nuclei']['url']}")
    if it["edb"]:
        refs.append(f"- Exploit-DB：https://www.exploit-db.com/exploits/{it['edb'][0]['id']}")
    if g.get("repos"):
        refs.append(f"- PoC 仓库：{g['repos'][0]['url']}")
    o.extend(refs)
    a("")
    a(f"#### 3.{n}.12 本地资产关联情况")
    a("")
    a("| 项目 | 结果 |")
    a("| --- | --- |")
    a("| 是否存在相关资产 | 待核查 |")
    a("| 关联资产数量 | 0 |")
    a("| 互联网暴露数量 | 0 |")
    a("| 当前状态 | 待核查 |")
    a("")
    return "\n".join(o)


def render(day, nar, outdir):
    _refresh_kev()
    b = load(f"{D}/base/{day}.json")
    gh = load(f"{D}/gh/{day}.json", {})
    items = b["items"]
    total = len(items)
    sev_cnt = {"严重": 0, "高危": 0, "中危": 0, "低危": 0, "未评分": 0}
    for i in items:
        sev_cnt[sev_of(i["cvss"]["score"])] += 1
    kev_items = [i for i in items if i["kev"]]
    poc_items = [i for i in items if poc_of(i, gh)[0] == "已公开"]
    scored = [i for i in items if i["cvss"]["score"] is not None]

    sel_ids = nar["selection"]
    by_id = {i["id"]: i for i in items}
    sel = [by_id[c] for c in sel_ids if c in by_id]
    nd = nar.get("detail_n", 3)

    L = []
    a = L.append
    a("---")
    a("title: 网络安全漏洞资讯日报")
    a(f"date: {day}")
    a(f"description: {day.replace('-', '年', 1).replace('-', '月', 1)}日网络安全漏洞、公开PoC、在野利用及修复信息汇总")
    a("tags:")
    a("  - 漏洞情报")
    a("  - CVE")
    a("  - 网络安全日报")
    a("---")
    a("")
    a("# 网络安全漏洞资讯日报")
    a("")
    y, m, d = day.split("-")
    a(f"> **报告日期：** {y}年{m}月{d}日  ")
    a(f"> **报告期次：** 2026年第{nar['issue']}期  ")
    import datetime as _dt
    def fmt(x, off=0):
        t = _dt.datetime.strptime(x.replace('.000', ''), "%Y-%m-%dT%H:%M:%S")
        return (t + _dt.timedelta(hours=off)).strftime("%Y-%m-%d %H:%M")
    a(f"> **统计周期：** {fmt(b['window'][0], 8)} 至 {fmt(b['window'][1], 8)}（Asia/Shanghai）／对应 UTC `{fmt(b['window'][0])}Z`–`{fmt(b['window'][1])}Z`  ")
    a(f"> **情报等级：** {nar['grade']}  ")
    a("> **编制单位：** 网络安全漏洞情报站（docs.allinu.eu.org）  ")
    a("> **数据来源：** NVD、CISA KEV、FIRST EPSS、OSV.dev、Exploit-DB、Metasploit Framework、Nuclei Templates、GitHub、厂商安全公告")
    a("")
    a(f"> **采集说明：** {nar['collect']}")
    a("")
    a(f"> **数据源扩展说明：** {nar['source_note']}")
    a("")
    a("**本期多源交叉覆盖率：**")
    a("")
    a("| 数据源 | 本期命中条目 | 用途 |")
    a("| --- | ---: | --- |")
    a(f"| NVD REST API 2.0 | {total} | 漏洞本体、CVSS、CWE、CPE、参考链接 |")
    a(f"| CISA KEV | {len(kev_items)} | 在野利用确认与处置期限 |")
    a(f"| FIRST EPSS | {sum(1 for i in items if i.get('epss'))} | 未来 30 天利用概率排序 |")
    a(f"| Metasploit Framework | {sum(1 for i in items if i['msf'])} | 模块化可利用性 |")
    a(f"| Exploit-DB | {sum(1 for i in items if i['edb'])} | 公开利用代码 |")
    a(f"| Nuclei Templates | {sum(1 for i in items if i.get('nuclei'))} | 可执行检测模板 |")
    a(f"| GitHub 仓库检索 | {sum(1 for i in items if (gh.get(i['id']) or {}).get('total'))} | 社区 PoC 仓库 |")
    ext_all = sum(1 for i in items if i.get("ext"))
    ext_poc = sum(1 for i in items if (i.get("ext") or {}).get("poc"))
    a(f"| 外部情报源（多源汇总页） | {ext_all} | PoC 标记交叉核验（该源覆盖 {ext_poc} 个带 PoC 的编号） |")
    a("")
    a("---")
    a("")
    a("## 一、今日漏洞态势")
    a("")
    a("### 1.1 漏洞统计")
    a("")
    a("| 指标 | 数量 | 指标 | 数量 |")
    a("| --- | ---: | --- | ---: |")
    a(f"| 收录漏洞总数（有效） | {total} | 严重漏洞 | {sev_cnt['严重']} |")
    a(f"| 高危漏洞 | {sev_cnt['高危']} | 中危漏洞 | {sev_cnt['中危']} |")
    a(f"| 低危漏洞 | {sev_cnt['低危']} | 暂无 CVSS 评分 | {sev_cnt['未评分']} |")
    a(f"| 公开 PoC（本期检得） | {len(poc_items)} | 在野利用（本期 KEV 新增） | {len(kev_today(day))} |")
    a(f"| CISA KEV（累计 / 本窗口新增） | {KEV_CAT['count']} / {len(kev_today(day))} | 需紧急处置（P0/P1） | {nar['urgent']} |")
    a("")
    a("> 统计口径：以 NVD 本窗口新发布（`publishedDate` 落在窗口内）且状态非 `Rejected` 的条目为总数；“公开 PoC”指 Nuclei / Metasploit / Exploit-DB / GitHub 四源中至少一源命中的编号；“在野利用”以 CISA KEV 收录为准。")
    a("")
    a("### 1.2 风险等级分布")
    a("")
    a("| 风险等级 | CVSS范围 | 数量 | 占比 |")
    a("| --- | ---: | ---: | ---: |")
    for k, rng in (("严重", "9.0–10.0"), ("高危", "7.0–8.9"), ("中危", "4.0–6.9"), ("低危", "0.1–3.9"), ("未评分", "—")):
        a(f"| {k} | {rng} | {sev_cnt[k]} | {pct(sev_cnt[k], total)} |")
    a("")
    a("### 1.3 今日重点关注")
    a("")
    for n, h in enumerate(nar["highlights"], 1):
        a(f"{n}. **`{h['cve']}`：{h['title']}**  ")
        a(f"   {h['text']}")
        a("")
    a("### 1.4 综合研判")
    a("")
    a(nar["judgement"])
    a("")
    a(f'!!! danger "研判结论：{nar["verdict_level"]}"')
    a(f"    {nar['verdict']}")
    a("")
    a("### 1.5 CISA KEV 新增与期限跟踪")
    a("")
    kt = kev_today(day)
    if kt:
        a(f"本期 CISA KEV 目录（catalogVersion `{KEV_CAT['catalogVersion']}`，累计 {KEV_CAT['count']} 条）于 **{day}** 新增 **{len(kt)}** 条：")
        a("")
        a("| CVE编号 | 厂商 / 产品 | 漏洞名称 | 收录日期 | 处置期限 | 勒索利用 |")
        a("| --- | --- | --- | --- | --- | --- |")
        for v in kt:
            a(f"| `{v['cveID']}` | {v['vendorProject']} / {v['product']} | {clean(v['vulnerabilityName'])} | {v['dateAdded']} | **{v['dueDate']}** | {v['knownRansomwareCampaignUse']} |")
        a("")
        a("> KEV 新增条目的原始 CVE 发布时间通常早于收录日期，因此不一定出现在本期 NVD 窗口统计中，需单独跟踪。")
    else:
        a(f"本期（{day}）CISA KEV 目录无新增条目（catalogVersion `{KEV_CAT['catalogVersion']}`，累计 {KEV_CAT['count']} 条）。")
    a("")
    ext_meta = b.get("ext_meta") or {}
    ext_hit = [i for i in items if (i.get("ext") or {}).get("poc")]
    ext_gap = [i for i in ext_hit if poc_of(i, gh)[0] == "未发现"]
    a("### 1.6 外部情报源交叉（多源汇总页）")
    a("")
    if ext_meta:
        a(f"外部情报源 `http://3.25.211.44:8080/report.html`（多源漏洞情报汇总，"
          f"聚合 NVD／CISA KEV／FIRST EPSS／OSV.dev／Exploit-DB／Nuclei／Metasploit／GitHub）"
          f"本次快照生成于 **{ext_meta.get('generated_at', '未知')}**，抓取于 {ext_meta.get('fetched_at', '—')}；"
          f"其库内累计 {ext_meta.get('totals', {}).get('全部漏洞', '—')} 条、"
          f"{ext_meta.get('totals', {}).get('有公开 PoC', '—')} 条带公开 PoC，"
          f"本次页面内嵌 {ext_meta.get('cve_count', '—')} 个编号快照。")
        a("")
        if ext_all:
            a(f"与本期窗口的交集：**{ext_all} 个编号**被该源收录，其中 **{len(ext_hit)} 个**带 PoC 标记。")
        else:
            a("与本期窗口**无交集**：该源页面内嵌的是最近更新的编号快照"
              f"（本次 {ext_meta.get('cve_count', '—')} 个），与本窗口发布时间不重叠，"
              "因此本期无法据此做增量交叉——这是快照式来源的固有限制，不是采集失败。")
        # 差异一：对方标记 PoC、本站四源未检出（属漏检，需补查）
        if ext_gap:
            a("")
            a(f"以下 **{len(ext_gap)} 个编号对方标记了 PoC，而本站四源（Nuclei／Metasploit／Exploit-DB／GitHub）未检出**。"
              "常见原因是 GitHub 检索受未认证配额限制（每期仅抽查 12 个编号），"
              "属**漏检而非确认无 PoC**，已在下表列明待补查：")
            a("")
            a("| CVE编号 | 对方 PoC 标记 | 对方 CVSS / EPSS | 本站四源 | 建议 |")
            a("| --- | --- | --- | --- | --- |")
            for i in ext_gap[:10]:
                e2 = i["ext"]
                epv = e2.get("epss")
                a(f"| `{i['id']}` | {'、'.join(e2.get('poc') or []) or '—'} | "
                  f"{e2.get('cvss') or '—'} / {(f'{epv * 100:.1f}%') if epv is not None else '—'} | 未检出 | "
                  f"人工复核，必要时提到 P1 排序 |")
        elif ext_all:
            a("")
            a("本期对方标记为有 PoC 的编号，本站四源均已覆盖，无漏检。")

        # 差异二：该源近两日更新、带 PoC，但不在本期 NVD 窗口内（存量复热，作补充线索）
        ext_file = f"{D}/extsrc.json"
        ext_idx_all = {}
        if os.path.exists(ext_file):
            ext_idx_all = (json.load(open(ext_file, encoding="utf-8")) or {}).get("index", {})
        try:
            from datetime import date, timedelta
            cutoff = (date(*map(int, day.split("-"))) - timedelta(days=2)).isoformat()
        except Exception:
            cutoff = ""
        win_ids = {i["id"] for i in items}
        supp = [dict(cve=k, **v) for k, v in ext_idx_all.items()
                if v.get("poc") and (v.get("updated") or "") >= cutoff
                and k not in win_ids]
        supp.sort(key=lambda x: (-(x.get("cvss") or 0), x["cve"]))
        if supp:
            a("")
            a(f"**补充线索（共 {len(supp)} 条，下表按 CVSS 列前 {min(len(supp), 10)} 条）**："
              "以下编号在该源中带 PoC 标记且近两日有更新，但**不在本期 NVD 窗口内**，"
              "属存量漏洞复热或迟报，**不计入本期统计口径**，仅作排查时顺带确认：")
            a("")
            a("| CVE编号 | 标题 | CVSS | EPSS | 对方 PoC | 更新时间 |")
            a("| --- | --- | ---: | ---: | --- | --- |")
            for x in supp[:10]:
                epv = x.get("epss")
                ttl = (x.get("title") or "")[:52].replace("|", "\\|")
                a(f"| `{x['cve']}` | {ttl or '—'} | {x.get('cvss') or '—'} | "
                  f"{(f'{epv * 100:.1f}%') if epv is not None else '—'} | "
                  f"{'、'.join(x['poc'])} | {x.get('updated') or '—'} |")
    else:
        a("本次未能获取外部情报源快照（页面不可达或结构变更），本节内容缺省；"
          "已在数据源说明中标注，不影响其余章节的结论。")
    a("")
    a("---")
    a("")
    a("## 二、重点漏洞清单")
    a("")
    a("| 序号 | CVE编号 | 漏洞名称 | 影响产品 | 等级 | CVSS | EPSS | PoC | 在野利用 | 优先级 |")
    a("| --- | --- | --- | --- | --- | ---: | ---: | --- | --- | --- |")
    for n, it in enumerate(sel, 1):
        poc, _ = poc_of(it, gh)
        ep = (it.get("epss") or {}).get("epss")
        a(f"| {n} | `{it['id']}` | {nar.get('detail', {}).get(it['id'], {}).get('title') or vtype(it)} | "
          f"{', '.join(it['products'][:1]) or '见公告'} | {sev_of(it['cvss']['score'])} | {it['cvss']['score'] or '—'} | "
          f"{f'{ep * 100:.1f}%' if ep else '—'} | {poc} | {'是' if it['kev'] else '否'} | {priority(it, poc, gh)} |")
    a("")
    a(f"> 上表为从本窗口 {total} 条有效条目中按「CVSS + KEV + EPSS + PoC + 可达性」加权筛出的 {len(sel)} 组重点编号；其余高危条目见第四节。")
    a("")
    a("---")
    a("")
    a("## 三、漏洞详情")
    a("")
    a("<!-- 层级规范：三/四/五/六 为 H2，每个漏洞为 H3（3.N），漏洞内小节为 H4（3.N.M） -->")
    a("")
    for n, it in enumerate(sel[:nd], 1):
        a(detail_section(n, it, gh, nar, day))
        a("---")
        a("")
    # 四、其他漏洞简报
    a("## 四、其他漏洞简报")
    a("")
    rest = [i for i in sel[nd:]]
    also = []
    for i in items:
        if i["id"] in sel_ids:
            continue
        if (i["cvss"]["score"] or 0) >= 8.5 and len(also) < nar.get("brief_extra", 10):
            also.append(i)
    brief = rest + also
    for it in brief:
        poc, srcs = poc_of(it, gh)
        a(f"### {it['id']} — {nar.get('brief', {}).get(it['id']) or vtype(it)}")
        a("")
        a("| 字段 | 内容 |")
        a("| --- | --- |")
        a(f"| 风险等级 | {sev_of(it['cvss']['score'])} |")
        a(f"| CVSS评分 | {it['cvss']['score'] or '—'}（CVSS {it['cvss']['version'] or '—'}） |")
        a(f"| CWE编号 | {', '.join('`' + c + '`' for c in it['cwe'][:2]) or '未标注'} |")
        bl = (nar.get("brief_prod", {}).get(it["id"])
              or ", ".join(pretty(x) for x in it["products"][:2])
              or guess_product(it["desc"]) or "见公告")
        a(f"| 影响产品 | {bl} |")
        a(f"| EPSS | {epss_txt(it)} |")
        a(f"| PoC状态 | {poc}{'（' + '、'.join(srcs) + '）' if srcs else ''} |")
        a(f"| 在野利用 | {'是' if it['kev'] else '否'} |")
        a(f"| 参考 | https://nvd.nist.gov/vuln/detail/{it['id']} |")
        a("")
        a("**漏洞描述：** " + clean(it["desc"])[:420])
        a("")
        a("**修复建议：** " + (nar.get("brief_fix", {}).get(it["id"]) or "按厂商公告升级至安全版本；无法升级时收敛访问面并加强日志监测。"))
        a("")
    a("---")
    a("")
    a("## 五、当日处置建议")
    a("")
    for n, s in enumerate(nar["advice"], 1):
        a(f"{n}. {s}")
    a("")
    a("---")
    a("")
    a("## 六、风险跟踪台账")
    a("")
    a("| 序号 | CVE编号 | 关联资产 | 等级 | 优先级 | 当前状态 | 完成时限 | 备注 |")
    a("|---|---|---|---|---|---|---|---|")
    for n, it in enumerate(sel[:12], 1):
        poc, _ = poc_of(it, gh)
        p = priority(it, poc, gh)
        due = nar.get("due", {}).get(it["id"]) or ("即时" if p == "P0" else ("24h" if p == "P1" else "3 个工作日"))
        a(f"| {n} | `{it['id']}` | 待核查 | {sev_of(it['cvss']['score'])} | {p} | 待核查 | {due} | "
          f"{'KEV 收录' if it['kev'] else ('PoC 公开' if poc == '已公开' else '—')} |")
    a("")
    a("---")
    a("")
    a("> **免责声明：** 本报告基于 NVD、CISA KEV、FIRST EPSS、OSV.dev、Exploit-DB、Metasploit、Nuclei 与 GitHub 等公开数据源自动采集并人工复核整理，仅用于网络安全防御、风险排查和授权安全测试。漏洞版本范围、PoC 状态与利用情况可能随时变化，处置前应以厂商最新公告为准。")
    a("")

    md = "\n".join(L)
    os.makedirs(outdir, exist_ok=True)
    fp = os.path.join(outdir, f"{day}.md")
    open(fp, "w").write(md)
    return fp, total, len(sel), len(brief)


if __name__ == "__main__":
    day = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else f"{D}/out"
    nar = json.load(open(f"{D}/narr/{day}.json"))
    print(render(day, nar, outdir))
