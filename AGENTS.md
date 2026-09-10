# docs-site 项目说明（Agent 指引）

## 项目概览

- MkDocs Material 站点，源码在本仓库；构建产物 `site/` 由 nginx 直接服务。
- 构建命令：`cd /home/ubuntu/docs-site && ./.venv/bin/mkdocs build`（exit code 必须为 0）。
- 每日日报：`docs/vulnerabilities/YYYY-MM-DD.md`，必须严格按 `daily_templates.md` 模板生成。
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

- 站点样式统一在 `docs/assets/extra-v2.css`（文件名带版本号，用于绕过 CDN 缓存；改样式优先改此文件，勿新建 `extra.css`）。
- 页面级注入（代码字体 preload、Cloudflare Web Analytics 等）：`hooks/head_inject.py`。
  Material 9.7+ 已重写主题系统，传统的 `overrides/partials/head.html`（`extends base.html`）覆盖方式失效，必须用 MkDocs hooks。
- 不要修改（除非任务明确要求）：`daily_templates.md`（模板规范）、`follow.opml`（RSS 订阅）、`mkdocs.yml`（构建配置）。
