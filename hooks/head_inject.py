"""页面级注入钩子：
1. <head> 顶部注入 Google tag (gtag.js, GA4)。
2. <head> 注入 Maple Mono NF CN 字体加载（FontsAPI 分片，preload + noscript 回退）。
3. </body> 前注入 Cloudflare Web Analytics 信标。
"""
GA_ID = 'G-4KC2T3CCXE'
GTAG = (
    '<!-- Google tag (gtag.js) -->'
    f'<script async src="https://www.googletagmanager.com/gtag/js?id={GA_ID}"></script>'
    '<script>\n'
    '  window.dataLayer = window.dataLayer || [];\n'
    '  function gtag(){dataLayer.push(arguments);}\n'
    "  gtag('js', new Date());\n"
    '\n'
    f"  gtag('config', '{GA_ID}');\n"
    '</script>'
    '<!-- End Google tag -->'
)

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
    head_inject = []
    if 'googletagmanager.com/gtag/js' not in output:
        head_inject.append(GTAG)
    if FONTSAPI not in output:
        head_inject.extend([FONTS_LINK, NOSCRIPT])
    if head_inject:
        output = output.replace('<head>', '<head>\n' + '\n'.join(head_inject), 1)
    if 'cloudflareinsights.com/beacon.min.js' not in output:
        output = output.replace('</body>', f'{CF_ANALYTICS}\n</body>', 1)
    return output
