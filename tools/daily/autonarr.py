#!/usr/bin/env python3
"""自动叙述生成：把结构化数据组合成中文研判文本（narr JSON）。

定时任务无人值守时使用本模块；若存在人工撰写的 narr（data/narr/{day}.json），
run.py 会优先使用人工版本，不覆盖。
"""
import json
import os
import re
import sys
from collections import Counter, OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import DOCS_VULN, load, path  # noqa: E402
from gen import CWE_MAP, poc_of, priority, sev_of, vtype  # noqa: E402  (vtype 为 CWE 映射，缺失时用 _type_of 兜底)

WATCH = [
    "cisco", "fortinet", "paloaltonetworks", "vmware", "ivanti", "citrix", "f5",
    "sonicwall", "atlassian", "microsoft", "oracle", "sap", "adobe", "ibm",
    "fortra", "progress", "beyondtrust", "solarwinds", "netapp", "zyxel", "dlink",
    "netgear", "tplink", "hikvision", "dahua", "wordpress", "apache", "nginx",
    "kubernetes", "docker", "gitlab", "jenkins", "linux", "azure", "aws",
    "sophos", "trendmicro", "mikrotik", "ruijie", "h3c", "huawei", "zte",
    "draytek", "totolink", "tenda", "php", "openssl", "spring", "tomcat",
]

TYPE_KNOW = {
    "输入验证不当": {
        "principle": ("根因是**同一份输入在不同处理路径上被解释成不同含义**（如归档类名、"
                      "文件名规范化、编码/解码次序不一致），而代码没有对这种歧义做归一化校验。"
                      "攻击者据此构造“对检查方无害、对执行方有害”的载荷："
                      "检查组件看到的是安全内容，实际执行路径写入或执行的是另一份内容。"
                      "这类缺陷很难靠单一黑名单拦住，通常需要上游修复解释逻辑。"),
        "path": "接收结构化输入并做二次解析的接口（文件/归档上传、导入、预览、内容校验）",
        "method": "POST multipart / POST JSON",
        "param": "同一语义存在两份元数据的字段（中央目录与本地头、大小写、URL 编码层数、路径分隔符）",
        "status": "校验接口返回通过，但落盘内容的哈希/路径与校验对象不一致",
    },
    "代码注入": {
        "principle": ("缺陷允许**把可控内容当作代码/表达式求值**（模板求值、动态 import、"
                      "eval 类调用、插件脚本）。一旦可注入，通常直接等价于在应用进程内执行任意代码，"
                      "且不依赖系统命令通道，常规命令注入防护规则无效。"),
        "path": "执行用户模板、公式、脚本或表达式的接口",
        "method": "POST",
        "param": "表达式/模板占位符、含 `#{` `${` `<%` 或函数调用语法的字段",
        "status": "响应中出现表达式求值结果，或进程异常退出",
    },
    "OS 命令注入": {
        "principle": ("缺陷的根因是**把用户可控数据直接拼进 shell 命令串**，而非以参数数组方式调用。"
                      "只要任一分隔符（`;`、`|`、`&`、换行、`$()`、反引号、`${IFS}`）未被拦截，"
                      "攻击者即可在宿主上以**服务进程身份**执行任意命令；容器化部署时逃逸范围限于容器，"
                      "但挂载了宿主目录或具备 K8s ServiceAccount 的场景可进一步横向。"),
        "path": "承载命令拼接功能的路由（导入/导出、转换、备份、诊断类接口）",
        "method": "POST（表单或 JSON）",
        "param": "被拼进命令的参数，含 `;` `|` `&` `$()` 反引号 `${IFS}` 换行",
        "status": "成功执行常返回 200 且响应含命令回显；拼接失败多为 500 或空响应",
    },
    "命令注入": {
        "principle": ("命令注入的根因是**外部输入未经白名单校验就进入命令执行路径**。"
                      "可利用性取决于注入点的引号上下文与转义情况，但只要能闭合引号或插入分隔符即可执行任意命令。"),
        "path": "调用系统命令的接口（系统设置、插件管理、诊断工具）",
        "method": "POST / GET",
        "param": "命令参数，含分隔符与控制字符",
        "status": "200 且响应长度异常增大，或出现命令输出片段",
    },
    "SQL 注入": {
        "principle": ("缺陷来自**拼接式 SQL 构造**（而非参数化查询），常见于排序字段、批量查询条件、"
                      "或框架层未覆盖的原始查询。可利用形态包括 UNION 回显、布尔/时间盲注、堆叠注入；"
                      "若数据库账号具备 FILE 权限，可进一步读写文件甚至执行系统命令。"),
        "path": "带查询参数的业务接口（列表、搜索、导出、统计）",
        "method": "GET / POST",
        "param": "进入 SQL 的过滤/排序/分页参数，含 `'` `\"` `)` `/**/` `SLEEP(` `UNION`",
        "status": "报错回显、响应时间随 `SLEEP` 变化、或返回行数异常",
    },
    "路径遍历": {
        "principle": ("根因是**路径拼接后未做规范化校验**，`../` 序列（含 URL 编码、双重编码、"
                      "Windows 反斜杠变体）可越过基目录。可直接读取配置文件、密钥、"
                      "其他租户数据；若与写文件能力结合，则可覆盖模板或脚本形成持久化。"),
        "path": "带文件名/路径参数的下载、预览、读取接口",
        "method": "GET",
        "param": "文件名或路径参数，含 `../` `..%2f` `%252e%252e` `..\\` 与绝对路径",
        "status": "返回非预期文件内容，或错误信息中泄露真实路径",
    },
    "认证绕过": {
        "principle": ("缺陷出在**身份判定逻辑本身**——可能是信任了客户端可控的头/参数、"
                      "校验分支可被跳过（如仅校验前缀、仅比对长度），或存在替代路径未走鉴权。"
                      "这类漏洞的后果通常不是单点泄露，而是**直接获得与目标身份等同的能力**，"
                      "因此即使 CVSS 中等也应按高优先级处置。"),
        "path": "鉴权中间件覆盖不到的路径（静态代理、健康检查、内部 API、旧版路由）",
        "method": "GET / POST",
        "param": "伪造的身份头（`X-Forwarded-*`、`X-User`、`role`）、令牌或路径变体",
        "status": "未携带凭据却返回 200 与业务数据，或返回管理员菜单/接口",
    },
    "缺失认证": {
        "principle": ("关键功能**完全没有挂载认证中间件**，或认证仅在 UI 层做、后端接口裸奔。"
                      "攻击者无需任何凭据即可调用敏感接口，常见于新增的管理端点、"
                      "内部调试接口被误暴露到公网。"),
        "path": "管理/调试类接口（未挂鉴权中间件）",
        "method": "GET / POST",
        "param": "无需参数，直接访问即可",
        "status": "匿名请求返回 200 与敏感数据或配置信息",
    },
    "反序列化": {
        "principle": ("缺陷是**对不可信数据执行反序列化**，攻击者可构造恶意对象图触发 `__wakeup`/"
                      "`readObject`/魔术方法链。是否可达 RCE 取决于目标环境是否存在可用的 gadget 链；"
                      "即便无链，也常可实现任意文件删除或 SSRF。"),
        "path": "接收序列化数据的接口（Cookie、缓存键、导入文件、RPC）",
        "method": "POST",
        "param": "序列化载荷（`O:..` / `rO0AB` / `aced0005` 特征）",
        "status": "500 伴随反序列化异常堆栈，或进程异常重启",
    },
    "越界写入": {
        "principle": ("内存安全缺陷：**边界检查缺失导致越界写**。可利用性取决于目标架构与缓解措施，"
                      "无 ASLR/无栈保护（嵌入式固件常见）时易于劫持控制流；"
                      "在有完整缓解的平台上通常先表现为崩溃（DoS），需配合信息泄露才能稳定利用。"),
        "path": "解析网络报文的协议处理路径（无需登录即可到达的解析器）",
        "method": "自定义协议报文 / 畸形 HTTP 请求",
        "param": "长度字段与内容不一致、超长字段、负数长度",
        "status": "进程崩溃并产生 core、服务重启、连接被异常重置",
    },
    "栈溢出": {
        "principle": ("栈上缓冲区未做长度校验，**超长输入覆盖返回地址**。嵌入式网络设备上"
                      "常缺少栈保护与 ASLR，单个报文即可劫持控制流；"
                      "服务以 root 运行时直接等价于设备完全失陷。"),
        "path": "协议解析入口（DHCPv6、UPnP、管理协议等无需认证的端口）",
        "method": "构造超长字段的协议报文",
        "param": "超过栈缓冲区长度的字段（域名、选项、长度前缀）",
        "status": "进程崩溃、设备重启、管理面短暂不可达",
    },
    "SSRF": {
        "principle": ("服务端**按用户提供的 URL 发起请求且未做目标白名单**，可探测内网、"
                      "访问云元数据接口（`169.254.169.254`）获取临时凭据，"
                      "或借 `gopher://`/`file://` 协议触达其他服务。"),
        "path": "接受 URL/回调地址的接口（Webhook、图片抓取、导入、预览）",
        "method": "POST",
        "param": "URL 参数，含内网地址、`file://`、`gopher://`、DNS 重绑定域名",
        "status": "服务端发起对内的连接，响应时间与目标端口相关",
    },
    "任意文件上传": {
        "principle": ("上传校验**仅依赖扩展名或 Content-Type**，未校验文件内容与落盘路径。"
                      "上传可执行脚本后访问即形成 webshell；"
                      "即便不可执行，也可覆盖配置文件或写入计划任务实现持久化。"),
        "path": "上传接口（头像、附件、导入、插件安装）",
        "method": "POST multipart",
        "param": "双扩展名、`.htaccess`/`.user.ini`、Content-Type 伪造、路径穿越文件名",
        "status": "上传后返回可直接访问的 URL，且该 URL 解析执行",
    },
    "跨站脚本": {
        "principle": ("输出未按上下文转义，**用户可控内容被当作 HTML/JS 执行**。"
                      "在管理后台场景下可窃取会话、以管理员身份执行操作。"),
        "path": "回显用户输入的页面（搜索、评论、错误页）",
        "method": "GET / POST",
        "param": "含 `<script>`、`onerror=`、`javascript:` 的输入",
        "status": "响应中原样回显未转义标签",
    },
    "信息泄露": {
        "principle": ("**敏感数据被返回给无权限主体**，或错误处理把内部细节（堆栈、路径、"
                      "配置、密钥）暴露到响应中。单条危害有限，但常为后续利用提供关键拼图。"),
        "path": "错误页、调试接口、导出接口",
        "method": "GET",
        "param": "触发异常的畸形参数、越权对象 ID",
        "status": "响应中出现堆栈、绝对路径、内部主机名或凭据",
    },
    "资源耗尽": {
        "principle": ("**缺少输入规模限制或复杂度控制**，单请求即可消耗大量 CPU/内存/连接，"
                      "导致服务不可用。可作为 DoS 直接利用，也可作为绕过限流的辅助手段。"),
        "path": "解析/计算密集型接口",
        "method": "POST",
        "param": "超长输入、深层嵌套结构、触发回溯的正则串",
        "status": "CPU/内存飙升、响应超时、进程 OOM 重启",
    },
    "权限提升": {
        "principle": ("**权限判定缺失或可绕过**，低权限主体可执行高权限操作。"
                      "在多租户或后台场景中直接导致横向越权。"),
        "path": "带角色/租户参数的接口",
        "method": "GET / POST",
        "param": "角色字段、对象 ID、租户标识",
        "status": "低权限凭据返回高权限数据或操作成功",
    },
}

GENERIC = {
    "principle": ("该条目在 NVD 中未给出更细的技术细节。按 CVSS 向量与 CWE 归类判断，"
                  "缺陷位于**输入校验或状态管理**层面，攻击者通过构造异常请求即可触发。"
                  "实际可利用性需结合部署形态（是否暴露于不可信网络）与厂商公告确认。"),
    "path": "与受影响功能对应的接口",
    "method": "GET / POST",
    "param": "异常长度、编码或特殊字符序列",
    "status": "非预期的 200/500 组合或异常响应体",
}


def _know(t):
    return TYPE_KNOW.get(t) or TYPE_KNOW.get(t.replace("（", "(").split("(")[0]) or GENERIC


DESC_TYPES = [
    (("sql injection",), "SQL 注入"),
    (("os command", "command injection", "shell command", "command execution"), "OS 命令注入"),
    (("remote code execution", "arbitrary code execution", "code execution"), "代码注入"),
    (("path traversal", "directory traversal", "path traversal"), "路径遍历"),
    (("deserial",), "反序列化"),
    (("server-side request forgery", "ssrf"), "SSRF"),
    (("authentication bypass", "bypass authentication", "auth bypass"), "认证绕过"),
    (("missing authentication", "without authentication", "no authentication",
      "unauthenticated"), "缺失认证"),
    (("authorization", "privilege escalation", "improper access control", "permission"), "权限提升"),
    (("cross-site scripting", "xss"), "跨站脚本"),
    (("unrestricted upload", "arbitrary file upload", "file upload"), "任意文件上传"),
    (("buffer overflow", "out-of-bounds write", "heap overflow", "stack overflow"), "越界写入"),
    (("use-after-free", "double free", "null pointer"), "越界写入"),
    (("denial of service", "resource exhaustion", "infinite loop"), "资源耗尽"),
    (("information disclosure", "exposes", "sensitive information"), "信息泄露"),
]


def _type_of(it):
    """优先用 CWE 映射出的类型；无 CWE（当日新披露常见）时按描述关键词判断"""
    t = vtype(it)
    if t != "通用缺陷":
        return t
    d = (it["desc"] or "").lower()
    for keys, name in DESC_TYPES:
        if any(k in d for k in keys):
            return name
    for c in it["cwe"]:
        if c in CWE_MAP:
            return CWE_MAP[c][0]
    return t


def _first(seq, default=""):
    return seq[0] if seq else default


STOP = {"The", "A", "An", "In", "This", "These", "It", "An", "Affected", "Multiple",
        "Some", "Various", "There", "Improper", "A vulnerability", "An issue", "An attacker",
        "An authentication", "SQL", "The affected", "Versions", "Prior", "Before"}

VENDOR_HINTS = [
    ("wordpress", "WordPress 生态"), ("fortinet", "Fortinet"), ("cisco", "Cisco"),
    ("microsoft", "Microsoft"), ("ibm", "IBM"), ("oracle", "Oracle"), ("sap", "SAP"),
    ("adobe", "Adobe"), ("atlassian", "Atlassian"), ("ivanti", "Ivanti"),
    ("vmware", "VMware"), ("apache", "Apache"), ("google", "Google"), ("apple", "Apple"),
    ("zoom", "Zoom"), ("gitlab", "GitLab"), ("jenkins", "Jenkins"), ("nginx", "Nginx"),
    ("huawei", "Huawei"), ("zyxel", "Zyxel"), ("dlink", "D-Link"), ("tenda", "Tenda"),
    ("totolink", "TOTOLINK"), ("mikrotik", "MikroTik"), ("ruijie", "Ruijie"),
    ("sonicwall", "SonicWall"), ("palo alto", "Palo Alto Networks"), ("f5", "F5"),
    ("progress", "Progress"), ("beyondtrust", "BeyondTrust"), ("solarwinds", "SolarWinds"),
    ("netapp", "NetApp"), ("synology", "Synology"), ("qnap", "QNAP"),
    ("trend micro", "Trend Micro"), ("sophos", "Sophos"), ("linux", "Linux"),
    ("windows", "Microsoft"), ("openssl", "OpenSSL"), ("php", "PHP"),
]


def _name_of(desc):
    """从英文描述里推断产品名（NVD 当日数据常无 CPE，只能靠文本）

    策略：先用固定句式精确截取，再退化为「取句首名词短语」——
    逐词累积，遇到动词／介词／版本词等分句标记即停止，最多 5 个词。
    宁可返回空（正文标注“受影响组件”），也不拼接跨句的误匹配。
    """
    if not desc:
        return ""
    d = " ".join(desc.split())

    pats = [
        r"[Tt]he ((?:[A-Z][\w.\-]*|\d[\w.\-]*)(?: [A-Za-z][\w.\-]*){0,4}) "
        r"(?:plugin|theme|extension|add-on|module|library)\b",
        r"vulnerability in ((?:[A-Z][\w.\-]*)(?: [A-Za-z][\w.\-]*){0,4}?)"
        r"(?=[,:.]| (?:before|through|prior|that|which|where|when|allows)\b)",
    ]
    for p in pats:
        m = re.search(p, d)
        if m:
            name = _clean_name(m.group(1))
            if name:
                return name

    # 句首名词短语：累积到分句动词/介词/版本词为止
    toks = d.replace(",", " ,").split()
    out = []
    for t in toks:
        low = t.lower().strip(".,:;")
        if low in _NAME_CUT or t == ",":
            break
        # 所有格（"Apache Kafka's …"）之后即进入描述细节，就此截断
        if low.endswith("'s") or low.endswith("’s"):
            out.append(t.strip(".,:;'’"))
            break
        out.append(t.strip(".,:;"))
        if len(out) >= 5:
            break
    return _clean_name(" ".join(out))


_NAME_CUT = {
    "is", "are", "was", "were", "be", "been", "being", "has", "have", "had",
    "allows", "allow", "contains", "contain", "does", "do", "did", "not",
    "fails", "fail", "validates", "validate", "permits", "enables", "accepts",
    "exposes", "uses", "use", "suffers", "leads", "results", "due", "could",
    "may", "might", "will", "would", "can", "should", "must",
    "before", "through", "prior", "after", "versions", "version", "vulnerable",
    "in", "on", "for", "of", "with", "via", "to", "by", "from", "at", "as",
    "when", "where", "which", "that", "who", "whose", "if", "while", "because",
    "plugin", "theme", "extension", "add-on", "module", "library", "software",
    "and", "or", "but", "also", "there", "this", "these", "those",
    "exposed", "affected", "vulnerable", "present", "exists", "exist",
    "discovered", "found", "identified", "impacted", "addressed", "fixed",
    "patched", "reachable", "exploitable", "installed", "configured",
    "provides", "provide", "offers", "offer", "implements", "supports", "includes",
    "sends", "receives", "stores", "loads", "performs", "writes", "reads",
    "parses", "processes", "handles", "manages", "runs", "executes", "opens",
    "creates", "deletes", "returns", "takes", "expects", "relies", "depends",
    "several", "many", "most", "few", "both", "paths", "systems", "versions",
    "restricts", "integrates", "integrate", "downloads", "uploads", "bypasses",
    "skips", "trusts", "passes", "leaks", "redirects", "hosts", "serves",
    "returns", "checks", "trusting", "accepting",
}


def _clean_name(raw):
    """清洗候选产品名；不像产品名则返回空串"""
    t = re.sub(r"\s+", " ", (raw or "").strip(" .,:;()[]'\"，、"))
    if not t:
        return ""
    toks = t.split()
    while toks and toks[-1].lower().strip(".,:;") in {
            "for", "in", "of", "and", "or", "with", "on", "to", "via", "is", "are",
            "the", "a", "an", "plugin", "theme", "software", "library",
            "this", "these", "those", "its", "their", "such"}:
        toks.pop()
    # 去掉结尾的版本号（"Jenkins 2.587" → "Jenkins"）与形容词尾缀（"… Stack-based"）
    while len(toks) > 1 and (re.match(r"^v?\d[\w.]*$", toks[-1])
                             or re.search(r"(?:-based|related|driven|like)$", toks[-1].lower())):
        toks.pop()
    if not toks or len(toks) > 5:
        return ""
    if toks[0].lower() in _NAME_STOP or toks[0] in STOP:
        return ""
    if toks[0].lower() in _GENERIC_HEADS:
        return ""
    # 函数/类名片段不是产品名
    if re.search(r"[()]|\._|_[a-z]|::[a-z]", t):
        return ""
    # 至少要有一个词具备“专有名词”特征：首字母大写/数字开头，或形如 jackson-databind
    if not any(re.match(r"^[A-Z0-9]", x) or re.match(r"^[a-z][\w.]*-[\w.\-]+$", x)
               for x in toks):
        return ""
    name = " ".join(toks)
    return name if len(name) >= 2 else ""


_NAME_STOP = {"the", "a", "an", "this", "these", "those", "it", "its", "their",
              "affected", "multiple", "some", "various", "improper", "insecure",
              "unspecified", "unknown", "certain", "all", "user", "users"}

# 描述句首常以缺陷类型而非产品名开头，这些词不能当作产品名
_GENERIC_HEADS = {
    "memory", "buffer", "stack", "heap", "sql", "cross", "cross-site", "denial",
    "improper", "insecure", "insufficient", "missing", "use", "out", "injection",
    "command", "code", "path", "data", "database", "information", "sensitive",
    "arbitrary", "remote", "local", "xml", "csv", "file", "files", "authentication",
    "authorization", "privilege", "server-side", "open", "unauthenticated",
    "vulnerability", "vulnerabilities", "multiple", "various", "affected", "certain",
    "incorrect", "unrestricted", "uncontrolled", "unvalidated", "unprotected",
    "svg", "html", "http", "json", "odoo", "php", "java", "python", "node",
    "deserialization", "type", "input", "output", "access", "permission",
    "certificate", "key", "token", "session", "header", "request", "response",
    "version", "versions", "product", "software", "application", "component",
    "system", "server", "client", "web", "website", "api", "plugin", "theme",
    "link", "following", "certain", "specific", "particular", "crafted",
    "insufficiently", "hardcoded", "hard-coded", "weak", "predictable",
    "unintended", "unnecessary", "inadequate", "untrusted", "illegitimate",
}


def _prod(it):
    if it["products"]:
        return it["products"][0].replace("_", " ")
    return _name_of(it["desc"]) or "受影响组件"


def _vendor(it):
    """只在 CPE 明确给出厂商时才署名——宁可留空，也不做易误判的关键词猜测"""
    if it["vendors"]:
        return it["vendors"][0].replace("_", " ")
    return ""


def _vendor_key(it):
    """仅用于选取去重，不影响正文表述"""
    if it["vendors"]:
        return it["vendors"][0]
    return _prod(it).split()[0] if _prod(it) else "unknown"


def _vec_phrase(v):
    parts = []
    if "AV:N" in v:
        parts.append("远程可达")
    elif "AV:L" in v:
        parts.append("需本地访问")
    if "PR:N" in v:
        parts.append("无需认证")
    elif "PR:L" in v:
        parts.append("需低权限账号")
    elif "PR:H" in v:
        parts.append("需高权限账号")
    if "UI:N" in v:
        parts.append("无需用户交互")
    elif "UI:R" in v:
        parts.append("需用户交互")
    if "AC:L" in v:
        parts.append("复杂度低")
    elif "AC:H" in v:
        parts.append("复杂度高")
    return "、".join(parts) if parts else "条件视部署而定"


def _epss_phrase(it):
    ep = it.get("epss")
    if not ep:
        return "EPSS 暂无评分（新披露条目通常滞后 1–2 天）"
    v = ep["epss"]
    if v >= 0.5:
        lvl = "属高利用概率区间"
    elif v >= 0.1:
        lvl = "处于中等偏上水平"
    elif v >= 0.01:
        lvl = "偏低"
    else:
        lvl = "极低"
    return f"EPSS {v * 100:.1f}%（第 {ep['pct'] * 100:.1f} 百分位），{lvl}"


def _poc_phrase(it, gh, day):
    st, srcs = poc_of(it, gh)
    if st == "已公开":
        later = []
        g = (gh or {}).get(it["id"]) or {}
        for r in g.get("repos") or []:
            if (r.get("created") or "")[:10] > day:
                later.append(r["full_name"])
        tail = f"（其中 {len(later)} 个仓库创建时间晚于本报告日期，属编制时回溯可见）" if later else ""
        return f"**已检出公开利用线索**：{'、'.join(srcs)}{tail}"
    return "四源均未检出公开 PoC"


def _title(it, k):
    p = _prod(it)
    t = _type_of(it)
    return f"{p} {t}（{it['cvss']['score']}）"


def _cond_short(it):
    v = it["cvss"]["vector"] or ""
    a = "未认证" if "PR:N" in v else ("需低权限" if "PR:L" in v else "需高权限")
    n = "远程" if "AV:N" in v else "本地"
    return f"{n}·{a}"


def score_items(items, gh):
    """综合排序：CVSS + KEV + PoC + EPSS + 可达性 + 关注厂商"""
    out = []
    for it in items:
        st, _ = poc_of(it, gh)
        s = (it["cvss"]["score"] or 0)
        s += 3.0 if it["kev"] else 0
        s += 2.0 if st == "已公开" else 0
        ep = (it.get("epss") or {}).get("epss", 0) or 0
        s += 3.0 * min(ep, 1.0)
        v = it["cvss"]["vector"] or ""
        if "PR:N" in v:
            s += 0.8
        if "AV:N" in v:
            s += 0.5
        if "AC:L" in v:
            s += 0.3
        key = " ".join(it["vendors"] + it["products"]).lower()
        if any(w in key for w in WATCH):
            s += 0.6
        out.append((round(s, 2), it))
    out.sort(key=lambda x: -x[0])
    return out


def pick(items, gh, want=8, per_vendor=2):
    """按厂商去重轮转挑选，避免单一批次（如 Oracle 一次性 1000+ 条）霸榜"""
    ranked = score_items(items, gh)
    cnt, sel = Counter(), []
    for _, it in ranked:
        if (it["cvss"]["score"] or 0) < 6.0 and len(sel) >= 5:
            continue
        vk = _vendor_key(it)
        if cnt[vk] >= per_vendor:
            continue
        cnt[vk] += 1
        sel.append(it)
        if len(sel) >= want:
            break
    return sel


def next_issue(day):
    """按已有日报推算期次：取最大期次 + 日期差"""
    best = (0, None)
    if os.path.isdir(DOCS_VULN):
        for fn in os.listdir(DOCS_VULN):
            if not fn.startswith("2026-") or not fn.endswith(".md"):
                continue
            d = fn[:-3]
            if d > day:
                continue
            try:
                txt = open(os.path.join(DOCS_VULN, fn), encoding="utf-8").read(1200)
            except Exception:
                continue
            m = re.search(r"报告期次：\*\*\s*2026年第(\d+)期", txt)
            if m:
                n = int(m.group(1))
                if n > best[0]:
                    best = (n, d)
    if not best[1]:
        return 1
    import datetime as dt
    from datetime import date
    y1, m1, d1 = map(int, best[1].split("-"))
    y2, m2, d2 = map(int, day.split("-"))
    delta = (date(y2, m2, d2) - date(y1, m1, d1)).days
    return best[0] + max(delta, 1)


def build(day, base, gh, kev_cat):
    items = base["items"]
    total = len(items)
    sev = Counter(sev_of(i["cvss"]["score"]) for i in items)
    kev_new = [v for v in kev_cat.get("vulnerabilities", []) if v.get("dateAdded") == day]
    kev_items = [i for i in items if i["kev"]]
    poc_items = [i for i in items if poc_of(i, gh)[0] == "已公开"]
    epss_cov = sum(1 for i in items if i.get("epss"))
    p0 = [i for i in items if priority(i, poc_of(i, gh)[0], gh) == "P0"]
    p1 = [i for i in items if priority(i, poc_of(i, gh)[0], gh) == "P1"]

    sel = pick(items, gh, want=8)
    detail_n = min(3, len(sel))
    win = base["window"]

    # ---------- 情报等级 ----------
    if kev_new or (p0 and any(i["kev"] for i in p0)):
        grade = "紧急"
    elif (p0 or len(kev_items) >= 2
          or any((i.get("epss") or {}).get("epss", 0) > 0.5 for i in items)
          or any((i["cvss"]["score"] or 0) >= 9.5 and poc_of(i, gh)[0] == "已公开" for i in items)):
        grade = "重要"
    else:
        grade = "常规"

    # ---------- 采集说明 ----------
    scored = sum(1 for i in items if i["cvss"]["score"] is not None)
    tv = Counter(_prod(i) for i in items)
    unlabeled = tv.pop("受影响组件", 0)
    tv = Counter({k: v for k, v in tv.items() if v >= 2}) or Counter({"各类组件": 0})
    top_vend = tv.most_common(3) or [("无法统计", 0)]
    vend_note = ("NVD 本窗口多数条目尚未完成分析（无 CPE 与官方评分），厂商分布按描述文本推断，仅供参考。"
                 if unlabeled > len(items) * 0.4 else "")
    def _cst(x):
        import datetime as _d
        t = _d.datetime.strptime(x.replace(".000", ""), "%Y-%m-%dT%H:%M:%S")
        return (t + _d.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M")

    collect = (
        f"窗口 `{win[0][:16]}Z`–`{win[1][:16]}Z`（北京时间 {_cst(win[0])} 至 {_cst(win[1])}），"
        f"NVD 返回 {total} 条有效条目（已剔除 `Rejected`），其中已给出 CVSS 评分 {scored} 条"
        f"（{scored / total * 100:.0f}%），EPSS 覆盖 {epss_cov} 条（{epss_cov / total * 100:.0f}%）。"
        f"厂商分布前三位为 {'、'.join(f'{k}（{v} 条）' for k, v in top_vend)}。{vend_note}"
        f"**CISA KEV {'本期新增 ' + str(len(kev_new)) + ' 条' if kev_new else '本期无新增'}**，"
        f"当前目录累计 {kev_cat.get('count', 0)} 条。"
    )

    # ---------- 数据源说明 ----------
    gh_hits = sum(1 for v in (gh or {}).values() if v.get("total"))
    nuc = sum(1 for i in items if i.get("nuclei"))
    msfc = sum(1 for i in items if i["msf"])
    edbc = sum(1 for i in items if i["edb"])
    src_bits = []
    if nuc:
        src_bits.append(f"Nuclei 模板命中 `{nuc}` 条")
    if msfc:
        src_bits.append(f"Metasploit 模块命中 `{msfc}` 条")
    if edbc:
        src_bits.append(f"Exploit-DB 命中 `{edbc}` 条")
    if gh_hits:
        src_bits.append(f"GitHub 仓库检索命中 `{gh_hits}` 条（本期按评分顺序抽查 "
                        f"{len(gh)} 个编号）")
    else:
        src_bits.append(f"GitHub 仓库检索未命中（本期按评分顺序抽查 {len(gh)} 个编号）")
    ext_all = sum(1 for i in items if i.get("ext"))
    ext_poc = sum(1 for i in items if (i.get("ext") or {}).get("poc"))
    if ext_all:
        src_bits.append(f"外部情报源（多源汇总页）收录本期 `{ext_all}` 个编号、"
                        f"其中 `{ext_poc}` 个带 PoC 标记")
    if not (nuc or msfc or edbc or gh_hits):
        src_bits.append("**四源均无命中，说明本期无已公开的可执行利用代码**")

    ep_vals = [(i.get("epss") or {}).get("epss") for i in items]
    ep_vals = [v for v in ep_vals if v]
    ep_max = max(ep_vals) if ep_vals else 0
    source_note = (
        "；".join(src_bits) + "。"
        f"EPSS 最高值为 **{ep_max * 100:.1f}%**"
        + ("，说明本期存在已被大规模扫描的目标。" if ep_max >= 0.5 else
           "，整体处于低热区，本期的排序依据因此更依赖**可达性与权限要求**而非利用热度。")
        + ("" if epss_cov / total > 0.5 else
           " 需注意 EPSS 数据集存在 1–2 天滞后，**新披露条目可能尚无评分**，不能据此判定“低风险”。")
    )

    # ---------- 重点关注 ----------
    highlights = []
    for it in sel[:4]:
        st, srcs = poc_of(it, gh)
        p = priority(it, st, gh)
        bits = [f"CVSS {it['cvss']['score']}（{_cond_short(it)}）"]
        epd = it.get("epss") or {}
        ep = epd.get("epss")
        if ep:
            bits.append(f"EPSS {ep * 100:.1f}%")
        if it["kev"]:
            bits.append(f"**已入 CISA KEV**（期限 {it['kev_due']}）")
        if st == "已公开":
            bits.append(f"公开 PoC（{'、'.join(srcs)}）")
        text = (f"{_oneline(it)} "
                f"该项 {('、'.join(bits))}，研判优先级 **{p}**。"
                + _extra_note(it, st, epd))
        highlights.append({"cve": it["id"], "title": _title(it, None), "text": text})

    # ---------- 综合研判 ----------
    kinds = Counter(_type_of(i) for i in sel)
    kind_top = "、".join(f"{k}（{v} 条）" for k, v in kinds.most_common(3))
    judgement = (
        f"本期 {total} 条有效条目中，严重 {sev['严重']} 条、高危 {sev['高危']} 条，"
        f"占比 {((sev['严重'] + sev['高危']) / total * 100):.0f}%。"
        f"从重点条目看，缺陷类型集中在 {kind_top}。"
        + (f"**CISA KEV 于本期收录 {len(kev_new)} 条**，意味着这些漏洞已被确认在野利用，"
           f"处置应从“评估”切换到“修复”。" if kev_new else
           "本期 KEV 无新增，暂无新增的“已确认在野利用”信号。")
        + (f" 已检出公开 PoC 的条目共 {len(poc_items)} 条，"
           f"{'其中含可武器化的 Metasploit 模块或 Exploit-DB 利用，' if (msfc or edbc) else ''}"
           f"披露到可用的间隔正在持续缩短。" if poc_items else
           " 本期未检出可执行 PoC，但“无 PoC”不等于“难利用”，多数条目仍可由单个 HTTP 请求触发。")
        + f" 需要紧急或 24 小时内处置（P0/P1）的条目共 {len(p0) + len(p1)} 条。"
    )

    if grade == "紧急":
        verdict_level = "紧急：24 小时内完成排查与修复"
        verdict = (f"本期存在 {len(kev_new)} 条 KEV 新增"
                   + (f"、{len(p0)} 条 P0" if p0 else "")
                   + "。建议当日完成资产测绘与版本确认，对暴露在互联网的实例优先升级或临时下线，"
                     "并回溯近 7 天访问日志与主机侧异常。")
    elif grade == "重要":
        verdict_level = "重要：本周内完成处置，优先处理互联网暴露面"
        verdict = ("本期无 KEV 新增，但存在高评分且低利用门槛的条目。"
                   "建议先按“是否可从不可信网络访问”做二分排查，"
                   "对确认暴露的实例执行升级，其余纳入常规补丁窗口。")
    else:
        verdict_level = "常规：按常规补丁节奏推进"
        verdict = ("本期无 KEV 新增、无高热 PoC，整体风险可控。"
                   "建议纳入常规补丁窗口，重点关注内部资产中受影响组件的版本分布。")

    # ---------- 详情叙述 ----------
    detail = {}
    for it in sel:
        k = _know(_type_of(it))
        st, srcs = poc_of(it, gh)
        ep = it.get("epss") or {}
        aff = _affected_phrase(it)
        fixv = _fix_phrase(it)
        detail[it["id"]] = {
            "title": _title(it, k),
            "vtype": _type_of(it),
            "tag": _tag(it, st),
            "oneline": _oneline(it),
            "summary": _summary(it, st, srcs, ep),
            "vendor": _vendor(it) or "NVD 未标注",
            "product": _prod(it),
            "kw": _prod(it),
            "affected": aff,
            "fixver": fixv,
            "deploy": _deploy(it),
            "access": _access_phrase(it),
            "config": _config_phrase(it),
            "config_note": "默认配置下即可能受影响" if "PR:N" in (it["cvss"]["vector"] or "")
                           else "需具备相应账号或特定配置",
            "complex": "低——单个请求即可触发" if "AC:L" in (it["cvss"]["vector"] or "")
                       else "高——需特定时序或环境条件",
            "principle": k["principle"],
            "detect_path": k["path"],
            "detect_method": k["method"],
            "detect_param": k["param"],
            "detect_status": k["status"],
            "fixsteps": _fixsteps(it, fixv),
            "mitigation": _mitigation(it, k),
            "ports": _ports(it),
        }

    # ---------- 简报 ----------
    sel_ids = [i["id"] for i in sel]
    brief, brief_prod, brief_fix = {}, {}, {}
    for it in sel[detail_n:]:
        brief[it["id"]] = _type_of(it)
        brief_prod[it["id"]] = _prod(it)
        brief_fix[it["id"]] = "升级至厂商公告给出的安全版本；无法升级时收敛访问面并加强日志监测。"
    # 额外补充高评分条目
    extra = 0
    for it in items:
        if it["id"] in sel_ids:
            continue
        if (it["cvss"]["score"] or 0) >= 8.5 and extra < 10:
            brief[it["id"]] = _type_of(it)
            brief_prod[it["id"]] = _prod(it)
            brief_fix[it["id"]] = "升级至厂商公告给出的安全版本；无法升级时收敛访问面并加强日志监测。"
            extra += 1

    # ---------- 处置建议 ----------
    advice = _advice(items, sel, kev_new, p0, p1, poc_items, ep_max)

    kev_new_ids = {v["cveID"] for v in kev_new}
    urgent = len(p0) + len(p1) + len(kev_new_ids - {i["id"] for i in p0} - {i["id"] for i in p1})

    return {
        "issue": next_issue(day),
        "grade": grade,
        "collect": collect,
        "source_note": source_note,
        "urgent": urgent,
        "highlights": highlights or [{
            "cve": sel[0]["id"] if sel else "—",
            "title": _title(sel[0], None) if sel else "本期无重点条目",
            "text": "本期条目普遍评分偏低且无公开利用线索，建议按常规补丁节奏处理。"}],
        "judgement": judgement,
        "verdict_level": verdict_level,
        "verdict": verdict,
        "selection": sel_ids,
        "detail_n": detail_n,
        "detail": detail,
        "brief": brief,
        "brief_prod": brief_prod,
        "brief_fix": brief_fix,
        "brief_extra": extra,
        "advice": advice,
        "generated_by": "auto",
    }


# ---------------------------------------------------------------- 文本片段
def _oneline(it):
    p = _prod(it)
    v = _vendor(it)
    t = _type_of(it)
    who = f"{v} 的 {p}" if v and v.lower() not in p.lower() else f"**{p}**"
    v3 = it["cvss"]["vector"] or ""
    cond = []
    if "AV:N" in v3:
        cond.append("可从网络直接触达")
    if "PR:N" in v3:
        cond.append("无需任何凭据")
    if "UI:N" in v3:
        cond.append("无需受害者交互")
    c = "、".join(cond) if cond else "需特定前置条件"
    noun = "" if t.endswith(("缺陷", "注入", "溢出", "绕过")) else " 缺陷"
    return f"{who} 存在 **{t}**{noun}，{c}。"


def _tag(it, st):
    v = it["cvss"]["vector"] or ""
    bits = []
    if "PR:N" in v:
        bits.append("未认证")
    if "AV:N" in v:
        bits.append("远程")
    bits.append(_type_of(it))
    if it["kev"]:
        bits.append("在野利用")
    elif st == "已公开":
        bits.append("PoC 可用")
    return " ".join(bits)


def _summary(it, st, srcs, ep):
    p = _prod(it)
    v = _vendor(it)
    t = _type_of(it)
    v3 = it["cvss"]["vector"] or ""
    s = []
    lead = f"{v} 的 {p}" if v and v.lower() not in p.lower() else p
    s.append(f"{lead} 存在 **{t}** 类型缺陷。"
             f"NVD 给出的 CVSS 评分为 **{it['cvss']['score']}**"
             f"（{it['cvss']['version']}，向量 `{v3 or '—'}`），"
             f"即 {_vec_phrase(v3)}。")
    if it["cwe"]:
        s.append(f"归类为 {'、'.join('`' + c + '`' for c in it["cwe"][:3])}。")
    # 从英文原文提取可读的受影响对象
    aff, fixv = _affected_phrase(it), _fix_phrase(it)
    if aff != "见厂商公告":
        s.append(f"受影响版本范围按描述为 `{aff}`。")
    if fixv != "见厂商公告":
        s.append(f"官方修复版本为 `{fixv}`。")
    if ep:
        s.append(f"FIRST EPSS 给出 **{ep['epss'] * 100:.1f}%** 的 30 天利用概率"
                 f"（第 {ep['pct'] * 100:.1f} 百分位，数据日期 {ep['date']}）。")
    else:
        s.append("该条目暂无 EPSS 评分，通常因披露时间过近而尚未纳入评分数据集。")
    if it["kev"]:
        s.append(f"**CISA 已于 {it['kev_date']} 将其纳入 KEV 目录**，"
                 f"要求 {it['kev_due']} 前完成修复，勒索软件利用标记为 {it['kev_ransom']}。")
    if st == "已公开":
        s.append(f"公开利用线索来自：{'、'.join(srcs)}。")
    else:
        s.append("Nuclei、Metasploit、Exploit-DB 与 GitHub 四源检索均未发现公开利用代码。")
    if it["patch"] or it["advisories"]:
        fixst = "厂商已发布补丁或修复版本。"
    elif fixv != "见厂商公告":
        fixst = f"描述中已明确修复版本为 `{fixv}`，按此升级即可。"
    else:
        fixst = "厂商公告尚未明确修复版本，需关注后续更新。"
    s.append(fixst)
    return " ".join(s)


def _extra_note(it, st, ep):
    v = it["cvss"]["vector"] or ""
    if it["kev"]:
        return ("KEV 收录意味着**已有确证的在野利用**，不应停留在“是否会被利用”的讨论上；"
                "若资产可从互联网访问，应按事件响应流程排查。")
    if st == "已公开" and (it["msf"] or it["edb"]):
        return ("已存在**可直接执行的利用代码**（模块化或 EDB 脚本），"
                "攻击者无需自行研究即可使用，这是本期最需要压缩处置窗口的一类。")
    if st == "已公开":
        if it["msf"]:
            return "已进入 Metasploit 模块库，意味着**拿到模块即可复用**，是最短的利用路径。"
        if it["edb"]:
            return "Exploit-DB 已有可执行脚本，攻击者无需自行研究即可使用。"
        if it.get("nuclei"):
            return "Nuclei 已提供检测模板，**批量扫描会很快覆盖到暴露资产**，检出即可能伴随尝试性利用。"
        return "已出现社区复现仓库，说明验证门槛不高，预计短期内会出现更多利用变体。"
    if ep and ep.get("epss", 0) > 0.3:
        return "EPSS 处于高位通常对应“已被扫描器批量覆盖”的状态，实际尝试可能已在发生。"
    if "PR:N" in v and "AV:N" in v:
        return ("**未认证 + 远程可达**是本期风险的共同特征——不需要任何前置条件，"
                "只要端口或接口可达即可尝试，因此风险主要由暴露面决定而非漏洞本身。")
    return "暂无公开利用线索，但利用门槛取决于具体部署形态，不宜按“低热度”直接降级。"


def _affected_phrase(it):
    d = " ".join((it["desc"] or "").split())
    m = re.search(r"(?:[Tt]hrough|[Uu]p to|[Aa]ffects? (?:versions? )?)\s+"
                  r"([0-9][0-9a-zA-Z.\-]{0,20})\s*(?:and earlier)?", d)
    if m:
        return "≤ " + m.group(1).strip(" .,")
    m = re.search(r"(?:[Bb]efore|[Pp]rior to|[Ee]arlier than)\s+(?:version\s+)?"
                  r"([0-9][0-9a-zA-Z.\-]{0,20})", d)
    if m:
        return "< " + m.group(1).strip(" .,")
    return "见厂商公告"


def _fix_phrase(it):
    d = " ".join((it["desc"] or "").split())
    m = re.search(r"(?:fixed in|addressed in|resolved in|patched in|fixed by|"
                  r"upgrade to|update to)\s+(?:version\s+|v)?([0-9][0-9a-zA-Z.\-]{0,20})", d)
    if m:
        return m.group(1).strip(" .,")
    return "见厂商公告"


def _deploy(it):
    key = " ".join(it["vendors"] + it["products"]).lower()
    if any(w in key for w in ("wordpress", "plugin", "theme", "drupal", "joomla")):
        return "站点插件/主题（自托管 CMS）"
    if any(w in key for w in ("router", "firmware", "openwrt", "nas", "camera")):
        return "网络设备/嵌入式固件"
    if any(w in key for w in ("azure", "aws", "gcp", "cloud", "saas")):
        return "云服务/托管平台"
    if any(w in key for w in ("windows", "linux", "kernel", "macos")):
        return "操作系统/内核"
    return "本地部署/自建"


def _access_phrase(it):
    v = it["cvss"]["vector"] or ""
    if "AV:N" in v:
        return "通过网络访问受影响接口或端口即可"
    if "AV:A" in v:
        return "需与目标处于同一广播域/相邻网段"
    return "需本地访问或已获得执行权限"


def _config_phrase(it):
    v = it["cvss"]["vector"] or ""
    return "否" if "PR:N" in v and "AC:L" in v else "视功能启用情况"


def _ports(it):
    key = " ".join(it["vendors"] + it["products"]).lower()
    table = [("wordpress", "80/443"), ("nginx", "80/443"), ("apache", "80/443"),
             ("tomcat", "8080/8443"), ("gitlab", "80/443/22"), ("jenkins", "8080"),
             ("mikrotik", "8291/80"), ("zyxel", "80/443/22"), ("cisco", "443/22"),
             ("fortinet", "443/10443"), ("ivanti", "443"), ("citrix", "443"),
             ("jenkins", "8080"), ("redis", "6379"), ("elasticsearch", "9200"),
             ("kubernetes", "6443"), ("docker", "2375/2376"), ("rdp", "3389"),
             ("smb", "445"), ("mysql", "3306"), ("postgres", "5432")]
    for k, v in table:
        if k in key:
            return v
    return "按产品默认端口"


def _fixsteps(it, fixv):
    s = [f"确认资产当前版本，与厂商公告给出的修复版本（`{fixv}`）比对；" if fixv != "见厂商公告"
         else "确认资产当前版本，并订阅厂商安全公告；"]
    if it["patch"]:
        s.append(f"按官方补丁升级：{it['patch'][0]}")
    else:
        s.append("升级至厂商公告给出的安全版本，升级前备份配置与数据并在测试环境验证兼容性")
    s.append("升级后复核版本号与补丁状态，并按 3.N.8 的检测项复查一次")
    if it["kev"]:
        s.append(f"KEV 期限为 {it['kev_due']}，需在该日期前完成闭环并留存证据")
    return s


def _mitigation(it, k):
    out = ["限制受影响接口/端口的互联网访问，仅允许可信源 IP",
           f"在 WAF/IPS 上针对该漏洞特征增加拦截规则（参数特征：{k['param']}）"]
    if it["kev"]:
        out.insert(0, "若短期无法升级，优先将该实例从公网下线或置于认证网关之后")
    v = it["cvss"]["vector"] or ""
    if "PR:L" in v:
        out.append("收紧账号权限，移除不必要的低权限账号与默认口令")
    out.append("开启并集中收集访问日志，保留至少 30 天用于回溯")
    return out


def _advice(items, sel, kev_new, p0, p1, poc_items, ep_max):
    a = []
    if kev_new:
        a.append(f"**KEV 新增 {len(kev_new)} 条（{'、'.join(v['cveID'] for v in kev_new[:4])}）**，"
                 f"按 CISA 期限倒排修复计划，优先核对边界设备与公网服务是否在用。")
    if p0:
        a.append(f"本期判定 **P0 共 {len(p0)} 条**（{'、'.join(i['id'] for i in p0[:4])}），"
                 f"要求当日完成资产测绘与版本确认。")
    if poc_items:
        a.append(f"已检出公开 PoC 的 **{len(poc_items)} 条**建议纳入本周补丁窗口；"
                 f"对已暴露实例回查近 7 天访问日志中的异常请求特征。")
    fams = Counter(_prod(i) for i in sel)
    fams.pop("受影响组件", None)
    fams = [(k, v) for k, v in fams.most_common(3) if v >= 2]
    if fams:
        a.append("集中出现的产品/组件（"
                 + "、".join(f"{k} {v} 条" for k, v in fams)
                 + "）建议整体拉取厂商公告，按产品线批量比对版本，而非逐条核对。")
    if ep_max < 0.05:
        a.append("本期 EPSS 整体偏低，**不要据此降低优先级**——EPSS 依赖“是否被扫描到”，"
                 "内网系统与嵌入式设备天然低分，但其可利用性往往更高。")
    a.append("对无法立即升级的组件，先在边界侧收敛访问面并开启针对性检测规则；"
             "修复完成后再做一次回归验证，确认补丁生效。")
    a.append("持续跟踪：将本期条目录入风险台账，下次报告中复核处置状态，避免重复出现。")
    return a


def main(day):
    base = load(path("base", f"{day}.json"))
    if not base:
        raise SystemExit(f"缺少 base 数据：{day}")
    gh = load(path("gh", f"{day}.json"), {}) or {}
    kev = load(path("kev.json"), {"count": 0, "vulnerabilities": []})
    nar = build(day, base, gh, kev)
    out = path("narr", f"{day}.json")
    if os.path.exists(out) and "--force" not in sys.argv:
        print(f"[narr] {day} 已存在人工/既有版本，跳过（--force 可覆盖）")
        return load(out)
    from common import dump
    dump(nar, out)
    print(f"[narr] {day} issue={nar['issue']} grade={nar['grade']} "
          f"sel={len(nar['selection'])} urgent={nar['urgent']}")
    return nar


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else __import__("common").today_cst())
