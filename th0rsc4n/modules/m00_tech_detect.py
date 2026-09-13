"""M00 - Technology Fingerprinting (Extended)
Detect 100+ web technologies: Frontend, Full-Stack, Backend, SSG, Mobile.
"""
import re
from bs4 import BeautifulSoup


# ==========================================
# TECH SIGNATURE DATABASE (100+ TECHS)
# ==========================================
TECH_SIGNATURES = {
    # ============================================================
    # KATEGORI A: FRONTEND MURNI
    # ============================================================
    "Vite": {
        "category": "A. Frontend",
        "patterns": [r"/@vite/", r"vite/client", r"type=\"module\"[^>]*src=\"[^\"]*vite"],
    },
    "Vue.js": {
        "category": "A. Frontend",
        "patterns": [r"vue(?:\.min)?\.js", r"vue\.runtime", r"data-v-[a-f0-9]{8}"],
        "html": [r'data-v-', r'v-cloak'],
    },
    "Create React App": {
        "category": "A. Frontend",
        "patterns": [r"react-scripts", r"static/js/main\.[a-f0-9]+\.js"],
        "html": [r'<div id="root"></div>'],
    },
    "React": {
        "category": "A. Frontend",
        "patterns": [r"react(?:\.min)?\.js", r"_reactRootContainer", r"react-dom"],
        "html": [r'data-reactroot'],
    },
    "Angular": {
        "category": "A. Frontend",
        "patterns": [r"angular(?:\.min)?\.js", r"ng-version", r"ng-app", r"main\.[a-f0-9]+\.js"],
        "html": [r'ng-version=', r'ng-app=', r'<app-root'],
    },
    "Svelte": {
        "category": "A. Frontend",
        "patterns": [r"svelte", r"__svelte"],
        "html": [r'class="svelte-'],
    },
    "SvelteKit": {
        "category": "A. Frontend",
        "patterns": [r"_app/immutable", r"__sveltekit"],
    },
    "Preact": {
        "category": "A. Frontend",
        "patterns": [r"preact(?:\.min)?\.js", r"preact-compat"],
    },
    "SolidStart": {
        "category": "A. Frontend",
        "patterns": [r"solid-js", r"solidjs", r"solid-start"],
    },
    "SolidJS": {
        "category": "A. Frontend",
        "patterns": [r"solid-js", r"solidjs"],
    },
    "Ember.js": {
        "category": "A. Frontend",
        "patterns": [r"ember(?:\.min)?\.js", r"ember-view", r"ember-cli"],
    },
    "Polymer": {
        "category": "A. Frontend",
        "patterns": [r"polymer", r"webcomponents"],
    },
    "Alpine.js": {
        "category": "A. Frontend",
        "patterns": [r"alpine(?:\.min)?\.js", r"x-data="],
    },
    "jQuery": {
        "category": "A. Frontend",
        "patterns": [r"jquery(?:\.min)?\.js", r"jquery-\d"],
    },
    "HTMX": {
        "category": "A. Frontend",
        "patterns": [r"htmx(?:\.min)?\.js", r"hx-get=", r"hx-post="],
    },
    
    # ============================================================
    # KATEGORI B: FULL-STACK
    # ============================================================
    "Next.js": {
        "category": "B. Full-Stack",
        "patterns": [r"__NEXT_DATA__", r"_next/static", r"/_next/"],
        "headers": {"x-powered-by": "Next.js"},
        "html": [r'id="__next"'],
    },
    "Nuxt": {
        "category": "B. Full-Stack",
        "patterns": [r"__NUXT__", r"_nuxt/"],
        "html": [r'id="__nuxt"'],
    },
    "Nuxt 3": {
        "category": "B. Full-Stack",
        "patterns": [r"__NUXT_DATA__", r"_nuxt/"],
    },
    "Remix": {
        "category": "B. Full-Stack",
        "patterns": [r"__remixContext", r"remix-run", r"@remix-run"],
    },
    "React Router": {
        "category": "B. Full-Stack",
        "patterns": [r"react-router", r"__reactRouterContext"],
    },
    "Astro": {
        "category": "B. Full-Stack",
        "patterns": [r"astro-island", r"data-astro-", r"astro-"],
    },
    
    # ============================================================
    # KATEGORI C: BACKEND & API
    # ============================================================
    "Python": {
        "category": "C. Backend",
        "headers": {"server": r"Python|Werkzeug|gunicorn|uvicorn"},
    },
    "Django": {
        "category": "C. Backend",
        "patterns": [r"csrfmiddlewaretoken", r"django"],
        "cookies": ["csrftoken", "sessionid"],
        "headers": {"server": r"WSGIServer"},
    },
    "Flask": {
        "category": "C. Backend",
        "headers": {"server": "Werkzeug"},
    },
    "FastAPI": {
        "category": "C. Backend",
        "headers": {"server": "uvicorn"},
        "patterns": [r'"detail":\s*"Not Found"'],
    },
    "Node.js": {
        "category": "C. Backend",
        "patterns": [r"node_modules", r"/node/"],
        "headers": {"x-powered-by": r"Express|Node"},
    },
    "Express": {
        "category": "C. Backend",
        "headers": {"x-powered-by": "Express"},
    },
    "Fastify": {
        "category": "C. Backend",
        "headers": {"x-powered-by": "Fastify"},
    },
    "NestJS": {
        "category": "C. Backend",
        "patterns": [r"nestjs", r"@nestjs"],
    },
    "Go (Golang)": {
        "category": "C. Backend",
        "headers": {"server": r"Go-http|Caddy|Golang"},
    },
    "Rust": {
        "category": "C. Backend",
        "headers": {"server": r"actix|rocket|axum"},
    },
    "PHP": {
        "category": "C. Backend",
        "headers": {"x-powered-by": "PHP"},
        "cookies": ["PHPSESSID"],
    },
    "Laravel": {
        "category": "C. Backend",
        "cookies": ["laravel_session", "XSRF-TOKEN"],
    },
    "Ruby on Rails": {
        "category": "C. Backend",
        "cookies": ["_rails_session", "_session_id"],
        "headers": {"x-powered-by": "Phusion Passenger"},
    },
    "Java": {
        "category": "C. Backend",
        "headers": {"server": r"Apache-Coyote|Tomcat|Jetty"},
        "cookies": ["JSESSIONID"],
    },
    "ASP.NET": {
        "category": "C. Backend",
        "headers": {"x-powered-by": "ASP.NET", "x-aspnet-version": r".*"},
        "cookies": ["ASP.NET_SessionId", ".AspNetCore"],
    },
    
    # ============================================================
    # KATEGORI D: STATIC SITE GENERATORS (SSG)
    # ============================================================
    "Zola": {
        "category": "D. SSG",
        "patterns": [r"zola", r'generator" content="Zola'],
        "html": [r'<meta name="generator" content="Zola'],
    },
    "VitePress": {
        "category": "D. SSG",
        "patterns": [r"vitepress", r"vp-doc"],
        "html": [r'class="vp-'],
    },
    "VuePress": {
        "category": "D. SSG",
        "patterns": [r"vuepress"],
    },
    "Docusaurus": {
        "category": "D. SSG",
        "patterns": [r"docusaurus", r"__docusaurus"],
        "html": [r'class="docusaurus'],
    },
    "Hugo": {
        "category": "D. SSG",
        "html": [r'<meta name="generator" content="Hugo'],
    },
    "Jekyll": {
        "category": "D. SSG",
        "html": [r'<meta name="generator" content="Jekyll'],
    },
    "11ty (Eleventy)": {
        "category": "D. SSG",
        "html": [r'<meta name="generator" content="Eleventy'],
    },
    "Hexo": {
        "category": "D. SSG",
        "html": [r'<meta name="generator" content="Hexo'],
    },
    "Gatsby": {
        "category": "D. SSG",
        "patterns": [r"gatsby", r"___gatsby"],
        "html": [r'id="___gatsby"'],
    },
    
    # ============================================================
    # KATEGORI E: MOBILE & ECOSYSTEM KHUSUS
    # ============================================================
    "Ionic": {
        "category": "E. Mobile & Niche",
        "patterns": [r"ionic", r"ion-app", r"ion-content"],
        "html": [r'<ion-app', r'<ion-content'],
    },
    "Storybook": {
        "category": "E. Mobile & Niche",
        "patterns": [r"storybook", r"@storybook"],
    },
    "Sanity": {
        "category": "E. Mobile & Niche",
        "patterns": [r"sanity\.io", r"cdn\.sanity\.io", r"@sanity"],
    },
    "xmcp": {
        "category": "E. Mobile & Niche",
        "patterns": [r"xmcp"],
    },
    
    # ============================================================
    # BUILD TOOLS
    # ============================================================
    "Webpack": {
        "category": "Build Tool",
        "patterns": [r"webpack", r"__webpack_require__", r"webpackChunk"],
    },
    "Parcel": {
        "category": "Build Tool",
        "patterns": [r"parcel", r"parcelRequire"],
    },
    "Rollup": {
        "category": "Build Tool",
        "patterns": [r"rollup"],
    },
    "esbuild": {
        "category": "Build Tool",
        "patterns": [r"esbuild"],
    },
    "Turbopack": {
        "category": "Build Tool",
        "patterns": [r"turbopack"],
    },
    "SWC": {
        "category": "Build Tool",
        "patterns": [r"swc"],
    },
    "Babel": {
        "category": "Build Tool",
        "patterns": [r"babel"],
    },
    
    # ============================================================
    # CSS FRAMEWORKS
    # ============================================================
    "Tailwind CSS": {
        "category": "CSS Framework",
        "patterns": [r"tailwind", r"cdn\.tailwindcss"],
        "html": [r'class="[^"]*\b(?:flex|grid|p-\d|m-\d|text-\w+-\d)'],
    },
    "Bootstrap": {
        "category": "CSS Framework",
        "patterns": [r"bootstrap(?:\.min)?\.(?:css|js)", r"bootstrap@\d"],
        "html": [r'class="[^"]*\b(?:container|row|col-\w+|btn-primary)'],
    },
    "Bulma": {
        "category": "CSS Framework",
        "patterns": [r"bulma(?:\.min)?\.css"],
    },
    "Foundation": {
        "category": "CSS Framework",
        "patterns": [r"foundation(?:\.min)?\.css"],
    },
    "Material UI": {
        "category": "CSS Framework",
        "patterns": [r"@mui/", r"MuiButton", r"makeStyles"],
    },
    "Chakra UI": {
        "category": "CSS Framework",
        "patterns": [r"chakra-ui", r"chakra-"],
    },
    "Ant Design": {
        "category": "CSS Framework",
        "patterns": [r"antd", r"ant-design"],
    },
    "Styled Components": {
        "category": "CSS Framework",
        "patterns": [r"styled-components"],
    },
    "Emotion": {
        "category": "CSS Framework",
        "patterns": [r"@emotion/"],
    },
    
    # ============================================================
    # CMS
    # ============================================================
    "WordPress": {
        "category": "CMS",
        "patterns": [r"wp-content", r"wp-includes", r"/wp-json/"],
        "html": [r'<meta name="generator" content="WordPress'],
    },
    "Drupal": {
        "category": "CMS",
        "patterns": [r"drupal", r"Drupal\.settings"],
        "html": [r'<meta name="generator" content="Drupal'],
    },
    "Joomla": {
        "category": "CMS",
        "html": [r'<meta name="generator" content="Joomla'],
    },
    "Ghost": {
        "category": "CMS",
        "html": [r'<meta name="generator" content="Ghost'],
    },
    "Contentful": {
        "category": "CMS",
        "patterns": [r"contentful"],
    },
    "Strapi": {
        "category": "CMS",
        "patterns": [r"strapi"],
    },
    
    # ============================================================
    # WEB SERVERS
    # ============================================================
    "Nginx": {
        "category": "Web Server",
        "headers": {"server": "nginx"},
    },
    "Apache": {
        "category": "Web Server",
        "headers": {"server": "Apache"},
    },
    "Caddy": {
        "category": "Web Server",
        "headers": {"server": "Caddy"},
    },
    "IIS": {
        "category": "Web Server",
        "headers": {"server": "Microsoft-IIS"},
    },
    "LiteSpeed": {
        "category": "Web Server",
        "headers": {"server": "LiteSpeed"},
    },
    "OpenResty": {
        "category": "Web Server",
        "headers": {"server": "openresty"},
    },
    
    # ============================================================
    # PLATFORMS & CDN
    # ============================================================
    "Vercel": {
        "category": "Platform",
        "headers": {"server": "Vercel", "x-vercel-id": r".*"},
    },
    "Netlify": {
        "category": "Platform",
        "headers": {"server": "Netlify", "x-nf-request-id": r".*"},
    },
    "Cloudflare Pages": {
        "category": "Platform",
        "headers": {"cf-ray": r".*", "server": "cloudflare"},
    },
    "GitHub Pages": {
        "category": "Platform",
        "headers": {"server": r"GitHub\.com"},
    },
    "Cloudflare": {
        "category": "CDN",
        "headers": {"server": "cloudflare", "cf-ray": r".*"},
    },
    "AWS CloudFront": {
        "category": "CDN",
        "headers": {"x-amz-cf-id": r".*", "via": r".*CloudFront.*"},
    },
    "Fastly": {
        "category": "CDN",
        "headers": {"x-served-by": r"cache-.*", "x-fastly-request-id": r".*"},
    },
    "Akamai": {
        "category": "CDN",
        "headers": {"server": r"AkamaiGHost"},
    },
    
    # ============================================================
    # BACKEND-AS-A-SERVICE
    # ============================================================
    "Firebase": {
        "category": "BaaS",
        "patterns": [r"firebase", r"firebaseapp\.com", r"firebaseio\.com"],
    },
    "Supabase": {
        "category": "BaaS",
        "patterns": [r"supabase", r"supabase\.co"],
    },
    "Appwrite": {
        "category": "BaaS",
        "patterns": [r"appwrite"],
    },
    "AWS Amplify": {
        "category": "BaaS",
        "patterns": [r"amplify"],
    },
    
    # ============================================================
    # ANALYTICS
    # ============================================================
    "Google Analytics": {
        "category": "Analytics",
        "patterns": [r"google-analytics\.com", r"gtag\(", r"googletagmanager"],
    },
    "Google Tag Manager": {
        "category": "Analytics",
        "patterns": [r"googletagmanager\.com"],
    },
    "Facebook Pixel": {
        "category": "Analytics",
        "patterns": [r"connect\.facebook\.net", r"fbq\("],
    },
    "Hotjar": {
        "category": "Analytics",
        "patterns": [r"hotjar", r"hj\("],
    },
    "Mixpanel": {
        "category": "Analytics",
        "patterns": [r"mixpanel"],
    },
    "Segment": {
        "category": "Analytics",
        "patterns": [r"segment\.(?:com|io)", r"analytics\.js"],
    },
    "Plausible": {
        "category": "Analytics",
        "patterns": [r"plausible\.io"],
    },
    "Vercel Analytics": {
        "category": "Analytics",
        "patterns": [r"vitals\.vercel-insights\.com", r"va\.vercel-scripts\.com"],
    },
    "Umami": {
        "category": "Analytics",
        "patterns": [r"umami"],
    },
    
    # ============================================================
    # JS LIBRARIES
    # ============================================================
    "GSAP": {
        "category": "Animation",
        "patterns": [r"gsap", r"TweenMax", r"TimelineMax"],
    },
    "Framer Motion": {
        "category": "Animation",
        "patterns": [r"framer-motion", r"framer\.com/motion"],
    },
    "Three.js": {
        "category": "3D",
        "patterns": [r"three(?:\.min)?\.js", r"THREE\."],
    },
    "D3.js": {
        "category": "Visualization",
        "patterns": [r"d3(?:\.min)?\.js", r"d3\.select"],
    },
    "Chart.js": {
        "category": "Visualization",
        "patterns": [r"chart(?:\.min)?\.js", r"Chart\("],
    },
    "Lodash": {
        "category": "Utility",
        "patterns": [r"lodash(?:\.min)?\.js", r"_\.(?:map|filter|reduce)"],
    },
    "Axios": {
        "category": "HTTP Client",
        "patterns": [r"axios(?:\.min)?\.js"],
    },
    "Socket.io": {
        "category": "Realtime",
        "patterns": [r"socket\.io", r"io\("],
    },
    "Swiper": {
        "category": "UI",
        "patterns": [r"swiper"],
    },
    "Font Awesome": {
        "category": "Icon",
        "patterns": [r"font-awesome", r"fontawesome", r"fa-"],
    },
    "Google Fonts": {
        "category": "Font",
        "patterns": [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"],
    },
    "Moment.js": {
        "category": "Utility",
        "patterns": [r"moment(?:\.min)?\.js"],
    },
    "Day.js": {
        "category": "Utility",
        "patterns": [r"dayjs"],
    },
    "Luxon": {
        "category": "Utility",
        "patterns": [r"luxon"],
    },
    
    # ============================================================
    # AUTH & PAYMENT
    # ============================================================
    "Auth0": {
        "category": "Auth",
        "patterns": [r"auth0", r"auth0\.com"],
    },
    "Clerk": {
        "category": "Auth",
        "patterns": [r"clerk\.(?:com|dev)", r"clerk-"],
    },
    "Firebase Auth": {
        "category": "Auth",
        "patterns": [r"firebase.*auth", r"firebaseui"],
    },
    "NextAuth": {
        "category": "Auth",
        "patterns": [r"next-auth", r"nextauth"],
    },
    "Stripe": {
        "category": "Payment",
        "patterns": [r"stripe\.com/v3", r"js\.stripe\.com"],
    },
    "Midtrans": {
        "category": "Payment",
        "patterns": [r"midtrans"],
    },
    "Xendit": {
        "category": "Payment",
        "patterns": [r"xendit"],
    },
    
    # ============================================================
    # SECURITY & MISC
    # ============================================================
    "reCAPTCHA": {
        "category": "Security",
        "patterns": [r"google\.com/recaptcha", r"grecaptcha"],
    },
    "Cloudflare Turnstile": {
        "category": "Security",
        "patterns": [r"challenges\.cloudflare\.com/turnstile"],
    },
    "hCaptcha": {
        "category": "Security",
        "patterns": [r"hcaptcha\.com"],
    },
    "PWA": {
        "category": "Feature",
        "patterns": [r"manifest\.json", r"serviceWorker"],
        "html": [r'<link rel="manifest"'],
    },
    "Web3": {
        "category": "Feature",
        "patterns": [r"web3", r"ethereum", r"metamask"],
    },
    "Open Graph": {
        "category": "SEO",
        "html": [r'<meta property="og:'],
    },
    "Twitter Card": {
        "category": "SEO",
        "html": [r'<meta name="twitter:'],
    },
    "Schema.org": {
        "category": "SEO",
        "html": [r'itemtype="https://schema\.org'],
    },
}


# ==========================================
# SCANNER
# ==========================================
def scan(scanner):
    """Detect technologies used by target."""
    r = scanner.get()
    if not r:
        scanner.add_finding("M00: Tech Detect", "INFO", "Tidak bisa detect teknologi")
        return
    
    html = r.text
    headers = {k.lower(): v for k, v in r.headers.items()}
    cookies = r.cookies.get_dict() if r.cookies else {}
    
    detected = []
    
    for tech_name, sig in TECH_SIGNATURES.items():
        found = False
        evidence = ""
        
        # Check HTML patterns
        if "patterns" in sig:
            for pattern in sig["patterns"]:
                if re.search(pattern, html, re.IGNORECASE):
                    found = True
                    evidence = f"pattern: {pattern[:40]}"
                    break
        
        # Check headers
        if not found and "headers" in sig:
            for header, value in sig["headers"].items():
                if header in headers:
                    if value == "*" or re.search(value, headers[header], re.IGNORECASE):
                        found = True
                        evidence = f"header {header}"
                        break
        
        # Check cookies
        if not found and "cookies" in sig:
            for cookie_name in sig["cookies"]:
                if cookie_name in cookies:
                    found = True
                    evidence = f"cookie: {cookie_name}"
                    break
        
        # Check HTML tags
        if not found and "html" in sig:
            for html_pattern in sig["html"]:
                if re.search(html_pattern, html, re.IGNORECASE):
                    found = True
                    evidence = f"html: {html_pattern[:40]}"
                    break
        
        if found:
            detected.append({
                "name": tech_name,
                "category": sig["category"],
                "evidence": evidence,
            })
    
    # Group by category
    by_category = {}
    for t in detected:
        by_category.setdefault(t["category"], []).append(t["name"])
    
    # Report
    if detected:
        scanner.add_finding("M00: Tech Detect", "INFO",
            f"Terdeteksi {len(detected)} teknologi",
            evidence=", ".join(sorted(set(t["name"] for t in detected))[:10]))
        
        for cat in sorted(by_category.keys()):
            techs = sorted(by_category[cat])
            scanner.add_finding("M00: Tech Detect", "INFO",
                f"  {cat}: {', '.join(techs)}")
    else:
        scanner.add_finding("M00: Tech Detect", "SAFE",
            "Tidak ada teknologi yang match signature (mungkin custom/static)")
    
    # Simpan ke scanner untuk report
    scanner.detected_tech = detected
    scanner.tech_by_category = by_category