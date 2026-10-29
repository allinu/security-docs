#!/usr/bin/env python3
"""每日漏洞日报 —— 公共配置与工具函数。

数据缓存目录固定在仓库内 `.cache/vulnpipe/`（已被 .gitignore 忽略），
不依赖任何临时目录，保证定时任务可重复执行。
"""
import datetime
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DATA = os.path.join(ROOT, ".cache", "vulnpipe", "data")
DOCS_VULN = os.path.join(ROOT, "docs", "vulnerabilities")
OUT_DIR = os.path.join(DATA, "..", "out")
OUT_DIR = os.path.abspath(OUT_DIR)

for _d in ("", "/nvd", "/base", "/gh", "/narr"):
    os.makedirs(DATA + _d, exist_ok=True)


def path(*parts):
    return os.path.join(DATA, *parts)


def load(fp, default=None):
    if not os.path.exists(fp):
        return default
    with open(fp, encoding="utf-8") as f:
        return json.load(f)


def dump(obj, fp):
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)


def today_cst():
    """返回北京时间当天（UTC+8，不依赖系统时区设置）"""
    return (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d")


def window_for(day):
    """报告日 D 的采集窗口 = (D-2)T21:00Z ~ (D-1)T21:00Z，即北京时间 D-1 05:00 至 D 05:00。

    与历史存档口径一致（报告在国内上午发布，覆盖此前 24 小时）。
    """
    from datetime import date, timedelta

    y, m, d = map(int, day.split("-"))
    d0 = date(y, m, d)
    s = (d0 - timedelta(days=2)).isoformat() + "T21:00:00.000"
    e = (d0 - timedelta(days=1)).isoformat() + "T21:00:00.000"
    return s, e


def age_days(fp):
    """文件距今天数；文件不存在返回一个很大的数"""
    if not os.path.exists(fp):
        return 10 ** 6
    return (datetime.datetime.now().timestamp() - os.path.getmtime(fp)) / 86400.0
