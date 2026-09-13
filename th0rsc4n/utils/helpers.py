from urllib.parse import urlparse

def normalize_url(url):
    """Normalisasi URL."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not url.endswith("/"):
        url += "/"
    return url

def is_valid_url(url):
    """Validasi format URL."""
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except:
        return False

def extract_domain(url):
    """Ambil domain dari URL."""
    return urlparse(url).netloc

def truncate(text, length=80):
    """Potong teks panjang."""
    return text[:length] + "..." if len(text) > length else text