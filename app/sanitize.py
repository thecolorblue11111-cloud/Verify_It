import bleach

def sanitize_html(html):
    allowed_tags = ['b', 'i', 'u', 'br', 'p', 'ul', 'li', 'ol', 'a']
    return bleach.clean(html, tags=allowed_tags, strip=True)