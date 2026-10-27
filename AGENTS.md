# docs-site 项目说明（Agent 指引）

## 项目概览

- MkDocs Material 站点，源码在本仓库；构建产物 `site/` 由 nginx 直接服务。
- 构建命令：`cd /home/ubuntu/docs-site && ./.venv/bin/mkdocs build`（exit code 必须为 0）。
- 每日日报：`docs/vulnerabilities/YYYY-MM-DD.md`，必须严格按 `daily_templates.md` 模板生成。
- 多源汇总补充：`http://3.25.211.44:8080/report.html` 是 **NVD、CISA KEV、FIRST EPSS、OSV.dev、Exploit-DB、Nuclei、Metasploit、GitHub** 的聚合去重层，不是第九类独立统计源。以 CVE ID 为主键去重，保留各原始来源归属；对既有日报先保持原报告统计周期和完整结构，再从页面 `detail-data` JSON 以 `published`/`modified` 时间筛选窗口内记录。已收录 CVE 补充 PoC、KEV、EPSS 和原始链接，未收录但具风险或公开 PoC 的 CVE 按日报既有“漏洞详情”或“其他漏洞简报”结构补齐。页面未标记 PoC/KEV 只能写作“快照未标记”，不得推断为不存在。
- VulnHOT 补充：优先使用匿名只读 API `https://vulnhot.com/api/v1/items?mode=selected&window=24h&by=published`；RSS 备用为 `https://vulnhot.com/feed.xml`（精选）、`https://vulnhot.com/feed/all.xml`（近 7 天已去重动态）与 `https://vulnhot.com/feed/daily.xml`（日报）。对在野利用、PoC、通告、供应链和事件，分别订阅 `https://vulnhot.com/feed/category/exploited.xml`、`poc.xml`、`advisory.xml`、`supply-chain.xml`、`incident.xml`。VulnHOT 是策展聚合源，按 `publishedAt` 划入统计窗口、按 CVE ID 或事件主题去重，并以 `links.original` 的原始通告/报道核验事实；其摘要或标签不能单独作为 PoC、在野利用或修复状态的结论。请求须遵循响应的 `Cache-Control`、`ETag`/`If-None-Match` 与 `Retry-After`。
- 站点地址：https://docs.allinu.eu.org

## 部署链路（重要！）

```
访客浏览器
  → Cloudflare（代理 + Web Analytics 信标）
  → SafeLine（雷池）WAF（已启用人机验证，自动请求会被拦截）
  → WireGuard 回源
  → 本机 nginx 源站监听器 10.77.0.1:15679
    server_name docs.allinu.eu.org / root /home/ubuntu/docs-site/site
```

**副作用提示**：WAF 人机验证对所有无 JS 的客户端返回 468，因此搜索引擎收录、IM 链接预览、Google Analytics 后台的「检测 Google 代码」等第三方验证都会失败——这属于 WAF 行为，不是站点/代码问题（代码正确性以源站回源口输出为准）。真人浏览器可自动通过 JS 挑战。

## 发布确认规范

- **权威校验（判断发布成功与否以此为准）**：

  ```
  curl -fsS -H 'Host: docs.allinu.eu.org' -o /dev/null -w '%{http_code}' http://10.77.0.1:15679/
  ```

  预期 `200`。同理可校验具体页面，例如 `http://10.77.0.1:15679/vulnerabilities/`。

- **公网 curl 返回 468 属正常现象，不是部署故障**：`curl https://docs.allinu.eu.org/` 会命中 SafeLine WAF 的反爬/人机验证，返回 `468` 或人机验证页（可能含 `/.safeline/` 特征、`sl-session` cookie、`via: 1.1 Caddy` 响应头）。
  - 不要因此重试发布、不要反复更换 User-Agent / HTTP 版本尝试绕过。
  - 报告中照实记录「公网 468（WAF 反爬，非故障）」即可，结论以源站校验为准。

## 样式与配置约定

- 站点样式统一在 `docs/assets/extra-v3.css`（文件名带版本号，用于绕过 CDN 缓存；改样式请在此基础上改内容并递增版本号，同步更新 `mkdocs.yml` 的 `extra_css`，勿新建 `extra.css`）。
- 页面级注入：`hooks/head_inject.py`，目前包含三部分——Google tag (gtag.js, GA4) 注入 `<head>` 顶部、Maple Mono NF CN 字体 preload（FontsAPI）、Cloudflare Web Analytics 信标（`</body>` 前）。
  Material 9.7+ 已重写主题系统，传统的 `overrides/partials/head.html`（`extends base.html`）覆盖方式失效，必须用 MkDocs hooks。
- 不要修改（除非任务明确要求）：`daily_templates.md`（模板规范）、`follow.opml`（RSS 订阅）、`mkdocs.yml`（构建配置）。
