"""在每页 <head> 注入 Maple Mono NF CN 字体加载（FontsAPI 分片，preload + noscript 回退）。"""
import re

FONTS_LINK = (
    '<link href="https://fontsapi.zeoseven.com/442/main/result.css" '
    "onload=\"this.rel='stylesheet'\" rel=\"preload\" as=\"style\" crossorigin />"
)
NOSCRIPT = (
    '<noscript><link rel="stylesheet" '
    'href="https://fontsapi.zeoseven.com/442/main/result.css" /></noscript>'
)


def on_post_page(output: str, page, config) -> str:
    if 'fontsapi.zeoseven.com/442/main/result.css' in output:
        return output
    return output.replace('<head>', f'<head>\n{FONTS_LINK}\n{NOSCRIPT}', 1)
