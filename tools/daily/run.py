#!/usr/bin/env python3
"""每日漏洞日报 —— 一键流水线（供定时任务调用）。

用法：
    python3 tools/daily/run.py                # 生成"今天"的日报并推送
    python3 tools/daily/run.py --day 2026-10-28
    python3 tools/daily/run.py --no-push      # 只生成，不提交推送
    python3 tools/daily/run.py --force        # 已存在日报时也重新生成

退出码：0 成功；非 0 失败（失败时不提交、不推送）。
"""
import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import autonarr  # noqa: E402
import pipeline  # noqa: E402
from common import DOCS_VULN, OUT_DIR, ROOT, dump, load, path, today_cst  # noqa: E402
import render as renderer  # noqa: E402


def log(msg):
    print(msg, flush=True)


def update_index():
    """刷新 docs/vulnerabilities/index.md 的日期归档块"""
    fp = os.path.join(DOCS_VULN, "index.md")
    if not os.path.exists(fp):
        log("[index] 未找到 index.md，跳过")
        return False
    dates = sorted(
        (f[:-3] for f in os.listdir(DOCS_VULN)
         if f.startswith("2026-") and f.endswith(".md")), reverse=True)
    block = "\n".join(f"- [{d}]({d}.md)" for d in dates)
    s = open(fp, encoding="utf-8").read()
    new, n = re.subn(r"<!-- DAILY_INDEX_START -->[\s\S]*?<!-- DAILY_INDEX_END -->",
                     "<!-- DAILY_INDEX_START -->\n" + block + "\n<!-- DAILY_INDEX_END -->", s)
    if n == 0:
        log("[index] 未找到 DAILY_INDEX 标记，跳过")
        return False
    open(fp, "w", encoding="utf-8").write(new)
    log(f"[index] 已更新，共 {len(dates)} 个日期")
    return True


def validate(fp, day):
    """发布前校验；返回 (ok, 错误列表)"""
    errs = []
    if not os.path.exists(fp):
        return False, ["文件未生成"]
    txt = open(fp, encoding="utf-8").read()
    need = [
        ("开头元数据", "title: 网络安全漏洞资讯日报"),
        ("统计周期", "**统计周期：**"),
        ("漏洞统计", "### 1.1 漏洞统计"),
        ("KEV 跟踪", "### 1.5 CISA KEV"),
        ("外部源交叉", "### 1.6 外部情报源交叉"),
        ("重点清单", "## 二、重点漏洞清单"),
        ("漏洞详情", "## 三、漏洞详情"),
        ("其他简报", "## 四、其他漏洞简报"),
        ("处置建议", "## 五、当日处置建议"),
        ("风险台账", "## 六、风险跟踪台账"),
        ("免责声明", "**免责声明：**"),
    ]
    for name, token in need:
        if token not in txt:
            errs.append(f"缺少章节：{name}（{token}）")
    for bad in ("待厂商确认", "产品指纹关键字", "见上文漏洞摘要与 NVD 原文描述",
                "| None |", "CVSS None", "EPSS None", "None（CVSS", "：None"):
        if bad in txt:
            errs.append(f"残留占位符：{bad}")
    if txt.count("CVE-") < 20:
        errs.append(f"条目过少（CVE 出现 {txt.count('CVE-')} 次），疑似采集失败")
    if len(txt) < 15000:
        errs.append(f"文件过短（{len(txt)} 字符）")
    if f"date: {day}" not in txt:
        errs.append(f"front matter 日期与报告日不符（应为 {day}）")
    return not errs, errs


def _git(args, cwd=ROOT):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True)


def git_publish(day, files):
    """提交并推送；任一环节失败抛异常，由调用方决定退出码"""
    def run(args):
        p = _git(args)
        if p.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} 失败：{(p.stderr or p.stdout).strip()[:400]}")
        return p.stdout

    run(["add", "--"] + files)
    if not _git(["status", "--porcelain", "--"] + files).stdout.strip():
        log("[git] 目标文件无变更，跳过提交")
        return False
    # 未配置身份时兜底，避免定时任务因缺少 user.name 失败
    if not _git(["config", "user.name"]).stdout.strip():
        run(["config", "user.name", "docs-bot"])
    if not _git(["config", "user.email"]).stdout.strip():
        run(["config", "user.email", "docs-bot@users.noreply.github.com"])

    msg = f"docs: {day} 每日漏洞情报"
    run(["commit", "-q", "-m", msg, "--"] + files)
    run(["push", "origin", "HEAD"])
    log(f"[git] 已提交并推送：{msg}")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", default=None, help="报告日期 YYYY-MM-DD，默认北京时间今天")
    ap.add_argument("--no-push", action="store_true", help="只生成，不提交推送")
    ap.add_argument("--force", action="store_true", help="覆盖已存在的日报/叙述")
    ap.add_argument("--per-day", type=int, default=12, help="GitHub 检索配额（编号数）")
    args = ap.parse_args()

    day = args.day or today_cst()
    out_fp = os.path.join(DOCS_VULN, f"{day}.md")
    log(f"=== 每日漏洞日报 {day} ===")

    if os.path.exists(out_fp) and not args.force:
        log(f"[skip] {day} 的日报已存在：{out_fp}")
        return 0

    # 1) 采集
    log("[1/5] 采集数据源（NVD / KEV / EPSS / EDB / MSF / Nuclei / GitHub）")
    pipeline.fetch_nvd(day, force=args.force)
    pipeline.fetch_kev(force=args.force)
    base = pipeline.build_base(day, force=True)
    if not base or base["total"] == 0:
        log("[fail] NVD 返回 0 条有效条目，终止（不发布空报告）")
        return 2
    pipeline.gh_poc(day, per_day=args.per_day)

    # 2) 叙述
    log("[2/5] 生成研判叙述")
    nar = autonarr.main(day) if args.force else (load(path("narr", f"{day}.json")) or autonarr.main(day))

    # 3) 渲染
    log("[3/5] 渲染 Markdown")
    fp, total, nsel, nbrief = renderer.render(day, nar, OUT_DIR)
    log(f"[render] {fp} total={total} selection={nsel} brief={nbrief}")

    # 4) 校验 + 发布到 docs
    log("[4/5] 校验并写入 docs")
    ok, errs = validate(fp, day)
    if not ok:
        log("[fail] 校验未通过，未写入仓库：")
        for e in errs:
            log("  - " + e)
        return 3
    os.makedirs(DOCS_VULN, exist_ok=True)
    with open(fp, encoding="utf-8") as f:
        content = f.read()
    with open(out_fp, "w", encoding="utf-8") as f:
        f.write(content)
    log(f"[docs] 已写入 {out_fp}（{len(content)} 字符）")
    update_index()

    # 5) 提交推送
    if args.no_push:
        log("[5/5] --no-push，跳过提交")
        return 0
    log("[5/5] 提交并推送到 GitHub")
    git_publish(day, [out_fp, os.path.join(DOCS_VULN, "index.md"),
                      os.path.join(ROOT, "tools")])
    log("=== 完成 ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
