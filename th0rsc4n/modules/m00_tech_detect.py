"""M00 - Technology Fingerprinting (robust)."""
import re
from bs4 import BeautifulSoup


# ==========================================
# SIGNATURE DATABASE
# ==========================================
TECH_SIGNATURES = {
    # Frontend
    "React": ["react", "_reactRootContainer", "react-dom"],
    "Next.js": ["__NEXT_DATA__", "/_next/", "__next"],
    "Vue.js": ["vue.js", "vue.min.js", "data-v-", "v-cloak"],
    "Nuxt": ["__NUXT__", "_nuxt/", "__nuxt"],
    "Angular": ["ng-version", "ng-app", "angular.min.js"],
    "Svelte": ["svelte", "__svelte"],
    "SvelteKit": ["_app/immutable", "__sveltekit"],
    "Astro": ["astro-island", "data-astro-"],
    "Remix": ["__remixContext", "remix-run"],
    "Alpine.js": ["alpine.js", "x-data="],
    "jQuery": ["jquery.min.js", "jquery-3", "jquery-2", "jquery-1"],
    "HTMX": ["htmx.min.js", "hx-get=", "hx-post="],
    "Preact": ["preact.min.js"],
    "SolidJS": ["solid-js", "solid.min.js"],
    "Ember.js": ["ember.min.js", "ember-view"],
    # Build Tool
    "Vite": ["/@vite/", "vite/client", "vite/dist"],
    "Webpack": ["webpack", "__webpack_require__"],
    "Turbopack": ["turbopack", "turbopack"],
    "esbuild": ["esbuild"],
    "Parcel": ["parcelRequire"],
    # CSS
    "Tailwind CSS": ["tailwind", "cdn.tailwindcss"],
    "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js", "bootstrap-5"],
    "Material UI": ["@mui/", "MuiButton", "makeStyles"],
    "Chakra UI": ["chakra-ui", "chakra-"],
    "Ant Design": ["antd", "ant-design"],
    # Backend
    "Express": ["express"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Flask": ["flask"],
    "Laravel": ["laravel"],
    "WordPress": ["wp-content", "wp-includes", "/wp-json/"],
    "Drupal": ["drupal"],
    "Ghost": ["ghost-"],
    # Analytics
    "Google Analytics": ["google-analytics.com", "gtag(", "analytics.js"],
    "Google Tag Manager": ["googletagmanager.com"],
    "Facebook Pixel": ["connect.facebook.net", "fbq("],
    "Hotjar": ["hotjar", "hj("],
    "Vercel Analytics": ["vitals.vercel-insights.com", "va.vercel-scripts.com"],
    "Plausible": ["plausible.io"],
    "Umami": ["umami"],
    # Libraries
    "GSAP": ["gsap", "TweenMax"],
    "Framer Motion": ["framer-motion"],
    "Three.js": ["three.min.js", "THREE."],
    "D3.js": ["d3.min.js", "d3.select"],
    "Chart.js": ["chart.min.js", "Chart("],
    "Lodash": ["lodash.min.js"],
    "Axios": ["axios.min.js"],
    "Socket.io": ["socket.io"],
    "Swiper": ["swiper"],
    "Font Awesome": ["font-awesome", "fontawesome"],
    "Google Fonts": ["fonts.googleapis.com"],
    "Moment.js": ["moment.min.js"],
    # Auth & Payment
    "Auth0": ["auth0"],
    "Clerk": ["clerk."],
    "NextAuth": ["next-auth"],
    "Stripe": ["stripe.com/v3", "js.stripe.com"],
    "Midtrans": ["midtrans"],
    "Xendit": ["xendit"],
    # BaaS
    "Firebase": ["firebase", "firebaseapp.com"],
    "Supabase": ["supabase"],
    # Security
    "reCAPTCHA": ["google.com/recaptcha", "grecaptcha"],
    "Cloudflare Turnstile": ["challenges.cloudflare.com/turnstile"],
    "PWA": ["manifest.json", "serviceWorker"],
}

CATEGORY_MAP = {
    "React": "Frontend", "Next.js": "Full-Stack", "Vue.js": "Frontend",
    "Nuxt": "Full-Stack", "Angular": "Frontend", "Svelte": "Frontend",
    "SvelteKit": "Frontend", "Astro": "Full-Stack", "Remix": "Full-Stack",
    "Alpine.js": "Frontend", "jQuery": "Library", "HTMX": "Library",
    "Preact": "Frontend", "SolidJS": "Frontend", "Ember.js": "Frontend",
    "Vite": "Build Tool", "Webpack": "Build Tool", "Turbopack": "Build Tool",
    "esbuild": "Build Tool", "Parcel": "Build Tool",
    "Tailwind CSS": "CSS Framework", "Bootstrap": "CSS Framework",
    "Material UI": "CSS Framework", "Chakra UI": "CSS Framework",
    "Ant Design": "CSS Framework",
    "Express": "Backend", "Django": "Backend", "Flask": "Backend",
    "Laravel": "Backend", "WordPress": "CMS", "Drupal": "CMS", "Ghost": "CMS",
    "Google Analytics": "Analytics", "Google Tag Manager": "Analytics",
    "Facebook Pixel": "Analytics", "Hotjar": "Analytics",
    "Vercel Analytics": "Analytics", "Plausible": "Analytics", "Umami": "Analytics",
    "GSAP": "Animation", "Framer Motion": "Animation",
    "Three.js": "3D", "D3.js": "Visualization", "Chart.js": "Visualization",
    "Lodash": "Utility", "Axios": "HTTP Client", "Socket.io": "Realtime",
    "Swiper": "UI", "Font Awesome": "Icon", "Google Fonts": "Font",
    "Moment.js": "Utility",
    "Auth0": "Auth", "Clerk": "Auth", "NextAuth": "Auth",
    "Stripe": "Payment", "Midtrans": "Payment", "Xendit": "Payment",
    "Firebase": "BaaS", "Supabase": "BaaS",
    "reCAPTCHA": "Security", "Cloudflare Turnstile": "Security",
    "PWA": "Feature",
}

# Header-based detect
HEADER_MAP = {
    "server:vercel": ("Vercel", "Platform"),
    "server:netlify": ("Netlify", "Platform"),
    "server:nginx": ("Nginx", "Web Server"),
    "server:apache": ("Apache", "Web Server"),
    "server:caddy": ("Caddy", "Web Server"),
    "server:microsoft-iis": ("IIS", "Web Server"),
    "server:litespeed": ("LiteSpeed", "Web Server"),
    "server:cloudflare": ("Cloudflare", "CDN"),
    "server:gunicorn": ("Gunicorn", "Backend"),
    "server:uvicorn": ("Uvicorn", "Backend"),
    "server:werkzeug": ("Werkzeug (Flask)", "Backend"),
    "x-powered-by:next.js": ("Next.js", "Full-Stack"),
    "x-powered-by:express": ("Express", "Backend"),
    "x-powered-by:php": ("PHP", "Backend"),
    "x-powered-by:asp.net": ("ASP.NET", "Backend"),
    "via:cloudfront": ("AWS CloudFront", "CDN"),
    "cf-ray": ("Cloudflare", "CDN"),
    "x-vercel-id": ("Vercel", "Platform"),
    "x-nf-request-id": ("Netlify", "Platform"),
    "x-amz-cf-id": ("AWS CloudFront", "CDN"),
}


def scan(scanner):
    """Detect technologies used by target."""
    # Coba 3 strategi ambil HTML
    html = ""
    headers = {}
    cookies = {}

    r = scanner.get()
    if r:
        html = r.text or ""
        headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        try:
            cookies = r.cookies.get_dict()
        except Exception:
            pass

    # Fallback: kalau html kosong, ambil manual via requests
    if not html or len(html) < 100:
        try:
            import requests
            rr = requests.get(scanner.target, headers=scanner.headers,
                              timeout=15, verify=False, allow_redirects=True)
            html = rr.text or ""
            headers = {k.lower(): v.lower() for k, v in rr.headers.items()}
            cookies = rr.cookies.get_dict() if rr.cookies else {}
        except Exception:
            pass

    if not html or len(html) < 100:
        scanner.add_finding("M00: Tech Detect", "INFO",
                            "Tidak bisa fetch HTML dari target")
        scanner.detected_tech = []
        scanner.tech_by_category = {}
        return

    detected = []
    html_lower = html.lower()

    # ========== DETECT VIA HTML ==========
    for tech_name, keywords in TECH_SIGNATURES.items():
        for kw in keywords:
            if kw.lower() in html_lower:
                detected.append({
                    "name": tech_name,
                    "category": CATEGORY_MAP.get(tech_name, "Other"),
                    "evidence": f"pattern: {kw}",
                })
                break

    # ========== DETECT VIA HEADERS ==========
    for key, (tech_name, category) in HEADER_MAP.items():
        if ":" in key:
            h_key, h_val = key.split(":", 1)
            if headers.get(h_key, "").find(h_val) != -1:
                if not any(d["name"] == tech_name for d in detected):
                    detected.append({
                        "name": tech_name,
                        "category": category,
                        "evidence": f"header {h_key}: {h_val}",
                    })
        else:
            # Header tanpa value (contoh: cf-ray)
            if key in headers:
                if not any(d["name"] == tech_name for d in detected):
                    detected.append({
                        "name": tech_name,
                        "category": category,
                        "evidence": f"header {key}",
                    })

    # ========== DETECT VIA COOKIES ==========
    cookie_map = {
        "PHPSESSID": ("PHP", "Backend"),
        "laravel_session": ("Laravel", "Backend"),
        "csrftoken": ("Django", "Backend"),
        "JSESSIONID": ("Java", "Backend"),
        "ASP.NET_SessionId": ("ASP.NET", "Backend"),
    }
    for ck, (tech_name, category) in cookie_map.items():
        if ck in cookies:
            if not any(d["name"] == tech_name for d in detected):
                detected.append({
                    "name": tech_name,
                    "category": category,
                    "evidence": f"cookie: {ck}",
                })

    # ========== GROUP BY CATEGORY ==========
    by_category = {}
    for t in detected:
        by_category.setdefault(t["category"], []).append(t["name"])

    # ========== REPORT ==========
    if detected:
        names = sorted(set(t["name"] for t in detected))
        scanner.add_finding(
            "M00: Tech Detect", "INFO",
            f"Terdeteksi {len(detected)} teknologi",
            evidence=", ".join(names[:10]),
        )
        for cat in sorted(by_category.keys()):
            techs = sorted(set(by_category[cat]))
            scanner.add_finding("M00: Tech Detect", "INFO",
                                f"  {cat}: {', '.join(techs)}")
    else:
        scanner.add_finding("M00: Tech Detect", "SAFE",
                            "Tidak ada teknologi yang match signature")

    # Save
    scanner.detected_tech = detected
    scanner.tech_by_category = by_category