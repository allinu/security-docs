"""页面级注入钩子：
1. <head> 注入 Maple Mono NF CN 字体加载（FontsAPI 分片，preload + noscript 回退）。
2. </body> 前注入 Cloudflare Web Analytics 信标。
"""
FONTSAPI = 'https://fontsapi.zeoseven.com/442/main/result.css'
FONTS_LINK = (
    f'<link href="{FONTSAPI}" '
    "onload=\"this.rel='stylesheet'\" rel=\"preload\" as=\"style\" crossorigin />"
)
NOSCRIPT = f'<noscript><link rel="stylesheet" href="{FONTSAPI}" /></noscript>'

CF_ANALYTICS = (
    '<!-- Cloudflare Web Analytics -->'
    "<script type='module' src='https://static.cloudflareinsights.com/beacon.min.js' "
    "data-cf-beacon='{\"token\": \"cf5233393435447a90deba45b580faeb\"}'></script>"
    '<!-- End Cloudflare Web Analytics -->'
)


def on_post_page(output: str, page, config) -> str:
    if FONTSAPI not in output:
        output = output.replace('<head>', f'<head>\n{FONTS_LINK}\n{NOSCRIPT}', 1)
    if 'cloudflareinsights.com/beacon.min.js' not in output:
        output = output.replace('</body>', f'{CF_ANALYTICS}\n</body>', 1)
    return output
