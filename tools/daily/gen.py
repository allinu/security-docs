#!/usr/bin/env python3
"""日报生成器：把 base/gh 数据 + narr 叙述渲染为 MkDocs Markdown"""
import json, os, sys, re

from common import DATA as D, OUT_DIR as _OUT

OUT = os.environ.get("VULN_OUT") or _OUT

CWE_MAP = {
    "CWE-20": ("输入验证不当", "A03:2021 注入", "CAPEC-153"),
    "CWE-22": ("路径遍历", "A01:2021 访问控制失效", "CAPEC-126"),
    "CWE-23": ("相对路径遍历", "A01:2021 访问控制失效", "CAPEC-126"),
    "CWE-59": ("链接跟随（符号链接）", "A01:2021 访问控制失效", "CAPEC-132"),
    "CWE-77": ("命令注入", "A03:2021 注入", "CAPEC-88"),
    "CWE-78": ("OS 命令注入", "A03:2021 注入", "CAPEC-88"),
    "CWE-79": ("跨站脚本（XSS）", "A03:2021 注入", "CAPEC-63"),
    "CWE-89": ("SQL 注入", "A03:2021 注入", "CAPEC-66"),
    "CWE-94": ("代码注入", "A03:2021 注入", "CAPEC-242"),
    "CWE-95": ("表达式语言注入", "A03:2021 注入", "CAPEC-242"),
    "CWE-119": ("内存缓冲区边界错误", "A06:2021 易受攻击组件", "CAPEC-100"),
    "CWE-120": ("缓冲区溢出", "A06:2021 易受攻击组件", "CAPEC-100"),
    "CWE-121": ("栈缓冲区溢出", "A06:2021 易受攻击组件", "CAPEC-100"),
    "CWE-122": ("堆缓冲区溢出", "A06:2021 易受攻击组件", "CAPEC-100"),
    "CWE-125": ("越界读取", "A06:2021 易受攻击组件", "CAPEC-540"),
    "CWE-190": ("整数溢出", "A06:2021 易受攻击组件", "CAPEC-92"),
    "CWE-200": ("敏感信息泄露", "A01:2021 访问控制失效", "CAPEC-116"),
    "CWE-269": ("权限管理不当", "A01:2021 访问控制失效", "CAPEC-122"),
    "CWE-276": ("默认权限不当", "A05:2021 安全配置错误", "CAPEC-1"),
    "CWE-284": ("访问控制不当", "A01:2021 访问控制失效", "CAPEC-122"),
    "CWE-287": ("认证机制不完善", "A07:2021 身份认证失效", "CAPEC-115"),
    "CWE-288": ("认证绕过（替代路径）", "A07:2021 身份认证失效", "CAPEC-115"),
    "CWE-290": ("认证绕过（欺骗）", "A07:2021 身份认证失效", "CAPEC-115"),
    "CWE-294": ("认证绕过（重放）", "A07:2021 身份认证失效", "CAPEC-60"),
    "CWE-306": ("关键功能缺失认证", "A07:2021 身份认证失效", "CAPEC-115"),
    "CWE-311": ("敏感数据明文存储/传输", "A02:2021 加密机制失效", "CAPEC-37"),
    "CWE-319": ("明文传输敏感信息", "A02:2021 加密机制失效", "CAPEC-157"),
    "CWE-326": ("加密强度不足", "A02:2021 加密机制失效", "CAPEC-112"),
    "CWE-352": ("跨站请求伪造（CSRF）", "A01:2021 访问控制失效", "CAPEC-62"),
    "CWE-362": ("竞态条件", "A04:2021 不安全设计", "CAPEC-26"),
    "CWE-377": ("不安全临时文件", "A05:2021 安全配置错误", "CAPEC-149"),
    "CWE-400": ("资源耗尽（DoS）", "A05:2021 安全配置错误", "CAPEC-147"),
    "CWE-401": ("内存泄漏致 DoS", "A06:2021 易受攻击组件", "CAPEC-147"),
    "CWE-416": ("释放后重用（UAF）", "A06:2021 易受攻击组件", "CAPEC-46"),
    "CWE-425": ("直接请求强制浏览", "A01:2021 访问控制失效", "CAPEC-127"),
    "CWE-427": ("不可信搜索路径", "A05:2021 安全配置错误", "CAPEC-471"),
    "CWE-434": ("危险类型文件上传", "A04:2021 不安全设计", "CAPEC-1"),
    "CWE-436": ("解释冲突", "A03:2021 注入", "CAPEC-33"),
    "CWE-444": ("HTTP 请求走私", "A03:2021 注入", "CAPEC-33"),
    "CWE-476": ("空指针解引用", "A06:2021 易受攻击组件", "CAPEC-129"),
    "CWE-502": ("不可信数据反序列化", "A08:2021 数据完整性失效", "CAPEC-586"),
    "CWE-532": ("日志中泄露敏感信息", "A09:2021 日志监控失效", "CAPEC-116"),
    "CWE-601": ("开放重定向", "A01:2021 访问控制失效", "CAPEC-194"),
    "CWE-611": ("XML 外部实体注入（XXE）", "A05:2021 安全配置错误", "CAPEC-221"),
    "CWE-639": ("IDOR 越权访问", "A01:2021 访问控制失效", "CAPEC-639"),
    "CWE-732": ("关键资源权限分配不当", "A01:2021 访问控制失效", "CAPEC-122"),
    "CWE-770": ("无限制资源分配", "A05:2021 安全配置错误", "CAPEC-147"),
    "CWE-787": ("越界写入", "A06:2021 易受攻击组件", "CAPEC-100"),
    "CWE-798": ("硬编码凭据", "A07:2021 身份认证失效", "CAPEC-191"),
    "CWE-824": ("未初始化指针访问", "A06:2021 易受攻击组件", "CAPEC-129"),
    "CWE-835": ("无限循环", "A05:2021 安全配置错误", "CAPEC-147"),
    "CWE-843": ("类型混淆", "A06:2021 易受攻击组件", "CAPEC-39"),
    "CWE-862": ("缺失授权", "A01:2021 访问控制失效", "CAPEC-122"),
    "CWE-863": ("授权校验不当", "A01:2021 访问控制失效", "CAPEC-122"),
    "CWE-917": ("表达式注入（OGNL/SpEL）", "A03:2021 注入", "CAPEC-242"),
    "CWE-918": ("服务端请求伪造（SSRF）", "A10:2021 SSRF", "CAPEC-664"),
    "CWE-1104": ("使用未维护的第三方组件", "A06:2021 易受攻击组件", "CAPEC-665"),
    "CWE-1321": ("原型污染", "A08:2021 数据完整性失效", "CAPEC-1"),
    "CWE-1333": ("正则表达式拒绝服务", "A05:2021 安全配置错误", "CAPEC-147"),
    "CWE-74": ("注入", "A03:2021 注入", "CAPEC-152"),
    "CWE-345": ("数据真实性验证不足", "A08:2021 数据完整性失效", "CAPEC-148"),
    "CWE-347": ("签名验证不当", "A08:2021 数据完整性失效", "CAPEC-463"),
    "CWE-404": ("资源释放不当", "A05:2021 安全配置错误", "CAPEC-147"),
    "CWE-407": ("算法复杂度低效", "A05:2021 安全配置错误", "CAPEC-147"),
    "CWE-522": ("凭据保护不足", "A07:2021 身份认证失效", "CAPEC-560"),
    "CWE-674": ("递归控制不当", "A05:2021 安全配置错误", "CAPEC-147"),
    "CWE-693": ("防护机制失效", "A05:2021 安全配置错误", "CAPEC-1"),
    "CWE-789": ("内存分配大小未受控", "A05:2021 安全配置错误", "CAPEC-130"),
    "CWE-943": ("查询逻辑特殊元素未中和", "A03:2021 注入", "CAPEC-152"),
    "CWE-1284": ("输入数量校验不当", "A03:2021 注入", "CAPEC-128"),
    "CWE-1327": ("绑定不受限 IP 地址", "A05:2021 安全配置错误", "CAPEC-1"),
}

TYPE_KEYS = [
    ("CWE-78", "OS 命令注入"), ("CWE-77", "命令注入"), ("CWE-94", "代码注入"),
    ("CWE-95", "表达式注入"), ("CWE-917", "表达式注入"), ("CWE-89", "SQL 注入"),
    ("CWE-79", "跨站脚本"), ("CWE-22", "路径遍历"), ("CWE-23", "路径遍历"),
    ("CWE-434", "任意文件上传"), ("CWE-502", "反序列化"), ("CWE-611", "XXE"),
    ("CWE-918", "SSRF"), ("CWE-352", "CSRF"), ("CWE-306", "缺失认证"),
    ("CWE-287", "认证绕过"), ("CWE-288", "认证绕过"), ("CWE-290", "认证绕过"),
    ("CWE-862", "缺失授权"), ("CWE-863", "授权不当"), ("CWE-639", "越权访问"),
    ("CWE-269", "权限提升"), ("CWE-787", "越界写入"), ("CWE-122", "堆溢出"),
    ("CWE-121", "栈溢出"), ("CWE-125", "越界读取"), ("CWE-416", "释放后重用"),
    ("CWE-476", "空指针解引用"), ("CWE-190", "整数溢出"), ("CWE-400", "资源耗尽"),
    ("CWE-1333", "ReDoS"), ("CWE-200", "信息泄露"), ("CWE-532", "日志泄露"),
    ("CWE-601", "开放重定向"), ("CWE-798", "硬编码凭据"), ("CWE-311", "明文存储"),
    ("CWE-1321", "原型污染"), ("CWE-444", "请求走私"),
]



def guess_product(desc):
    """从描述中猜产品名，用于 CPE 缺失场景的展示与测绘关键字"""
    if not desc:
        return ""
    d = desc.replace("\n", " ").strip()
    pats = [
        r"The ([A-Z][\w\-\. ]{1,40}?) (?:plugin|theme|extension|add-on|module) for",
        r"in the ([A-Z][\w\-\. ]{1,40}?) (?:plugin|theme)",
        r"The ([A-Z][\w\-\. ]{1,40}?) plugin",
        r"([A-Z][\w\-\. ]{1,40}?) is (?:a|an|the) [a-z]",
        r"In ([A-Z][\w\-\. ]{1,40}?) (?:before|through|versions|prior)",
        r"affects? ([A-Z][\w\-\. ]{1,40}?)[:.,]",
        r"vulnerability in ([A-Z][\w\-\. ]{1,40}?)[:.,]",
        r"([A-Z][\w\-\. ]{1,40}?) (?:through|could allow|allows|contains)",
    ]
    for p in pats:
        m = re.search(p, d)
        if m:
            name = m.group(1).strip(" .,:;")
            if 1 < len(name) <= 40 and not name.lower().startswith(("this", "the issue", "an ", "a ")):
                return name
    return ""


def sev_of(score):
    if score is None:
        return "未评分"
    if score >= 9:
        return "严重"
    if score >= 7:
        return "高危"
    if score >= 4:
        return "中危"
    return "低危"


def vtype(it):
    for c in it["cwe"]:
        for k, v in TYPE_KEYS:
            if c == k:
                return v
    return "通用缺陷"


def poc_of(it, gh):
    """返回 (状态, 来源列表)"""
    src = []
    if it.get("nuclei"):
        src.append("Nuclei 模板")
    if it["msf"]:
        src.append("Metasploit 模块")
    if it["edb"]:
        src.append("Exploit-DB")
    g = gh.get(it["id"]) or {}
    if g.get("total"):
        src.append(f"GitHub 仓库×{g['total']}")
    if it["poc_ref"]:
        src.append("公告引用 Exploit")
    if src:
        return "已公开", src
    return "未发现", []


def priority(it, poc, gh):
    s = 0
    if it["kev"]:
        s += 3
    if poc == "已公开":
        s += 2
    if (it["cvss"]["score"] or 0) >= 9:
        s += 2
    v = it["cvss"]["vector"] or ""
    if "PR:N" in v or "AC:L" in v or "AV:N" in v:
        s += 1
    ep = (it.get("epss") or {}).get("epss", 0)
    if ep and ep > 0.5:
        s += 1
    if s >= 6:
        return "P0"
    if s >= 4:
        return "P1"
    if s >= 2:
        return "P2"
    return "P3"


def cond_table(it):
    v = it["cvss"]["vector"] or ""
    net = "是" if "AV:N" in v else ("本地" if "AV:L" in v else "视场景")
    auth = "无需" if "PR:N" in v else ("普通用户" if "PR:L" in v else "管理员")
    ui = "不需要" if "UI:N" in v else ("需要" if "UI:R" in v else "视场景")
    ac = "低" if "AC:L" in v else ("高" if "AC:H" in v else "视场景")
    return net, auth, ui, ac


def attack_chain(it):
    t = vtype(it)
    vend = (it["vendors"] or ["目标产品"])[0]
    prod = (it["products"] or ["目标组件"])[0]
    if "命令" in t or "代码" in t or "注入" in t:
        mid = "构造携带命令/表达式载荷的请求"
        end = "以服务进程权限执行任意命令"
    elif "路径" in t:
        mid = "构造含路径穿越序列的请求"
        end = "读取/写入应用目录外的敏感文件"
    elif "认证" in t or "授权" in t or "越权" in t:
        mid = "直接访问受保护接口或伪造身份"
        end = "绕过认证获得未授权能力"
    elif "溢出" in t or "越界" in t or "重用" in t or "指针" in t:
        mid = "发送特制长度/结构的数据包"
        end = "破坏内存并劫持控制流"
    elif "上传" in t:
        mid = "上传绕过类型校验的恶意文件"
        end = "在服务器落地可执行内容"
    elif "SSRF" in t:
        mid = "提交可控 URL 使服务端发起请求"
        end = "探测内网或访问元数据接口"
    else:
        mid = "发送畸形输入触发缺陷逻辑"
        end = "造成信息泄露、拒绝服务或状态破坏"
    return (f"攻击者\n  └─ 定位暴露的 {prod}（{vend}）\n"
            f"      └─ {mid}\n"
            f"          └─ 触发 {', '.join(it['cwe'][:2]) or '缺陷'} 对应处理逻辑\n"
            f"              └─ {end}\n"
            f"                  └─ 横向利用或持久化（视环境）")


def fofa(it):
    prod = (it["products"] or [""])[0]
    vend = (it["vendors"] or [""])[0]
    kw = prod.replace("_", " ") if prod else vend.replace("_", " ")
    if not kw:
        kw = "产品指纹关键字"
    return kw


def epss_txt(it):
    ep = it.get("epss")
    if not ep:
        return "暂无数据"
    return f"{ep['epss'] * 100:.1f}%（第 {ep['pct'] * 100:.1f} 百分位，{ep['date']}）"


def kev_txt(it, day=None):
    if not it["kev"]:
        return "否（截至报告日未收录）"
    if day and it["kev_date"] > day:
        return f"是（{it['kev_date']} 收录，晚于本报告日期，属编制时回溯可见信息；期限 {it['kev_due']}）"
    return f"是（{it['kev_date']} 收录，期限 {it['kev_due']}）"
