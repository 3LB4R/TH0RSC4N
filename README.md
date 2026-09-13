# 🛡️ TH0RSC4N

**Brutal OWASP Top 10 Security Scanner** by [Thorranov](https://thorranov-portfolio.vercel.app)

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-red)](https://owasp.org/Top10/)

## 📖 Tentang

TH0RSC4N adalah CLI tool untuk audit keamanan website dengan **80+ skenario OWASP Top 10 2021** + deteksi teknologi (150+ tech). Cocok untuk pentester, developer, dan security enthusiast.

## ✨ Fitur

- ✅ **80+ skenario keamanan** OWASP Top 10 2021
- ✅ **Deteksi teknologi** — React, Next.js, Vue, Angular, Vite, dll (150+)
- ✅ **3 mode scan** — Quick (~5s), Normal (~15s), Deep (~60s)
- ✅ **Multi-format report** — HTML, JSON, Markdown
- ✅ **Export security config** — Vercel, Netlify, Nginx, Apache, Cloudflare, Express
- ✅ **Interactive mode** — ramah untuk pemula
- ✅ **Web UI** — scan via browser
- ✅ **Terminal hacker aesthetic** — hijau neon matrix

## 🚀 Instalasi

### Cara 1: Via Git Clone

```bash
git clone https://github.com/thorranov/th0rsc4n.git
cd th0rsc4n
pip install -e .
```

### Cara 2: Via pip (setelah publish ke PyPI)

```bash
pip install th0rsc4n
```

## 🎯 Cara Pakai

### Scan lengkap

```bash
th0rsc4n scan https://target.com
```

### Deep scan + simpan report

```bash
th0rsc4n scan https://target.com -m deep -o report --format all
```

### Deteksi teknologi saja

```bash
th0rsc4n tech https://target.com
```

### Mode interaktif (untuk pemula)

```bash
th0rsc4n interactive
```

### Export security config

```bash
th0rsc4n scan https://target.com --export-config nginx
```

### Web UI

```bash
th0rsc4n web
```

## 📋 Command Lengkap

| Command                  | Deskripsi                  |
| ------------------------ | -------------------------- |
| `th0rsc4n scan <url>`    | Scan keamanan OWASP Top 10 |
| `th0rsc4n tech <url>`    | Deteksi teknologi website  |
| `th0rsc4n headers <url>` | Cek security headers       |
| `th0rsc4n interactive`   | Mode interaktif            |
| `th0rsc4n web`           | Web UI di browser          |
| `th0rsc4n modes`         | Lihat semua mode           |
| `th0rsc4n quick <url>`   | Quick scan                 |
| `th0rsc4n deep <url>`    | Deep scan                  |
| `th0rsc4n init`          | Setup config               |

## 🎬 Demo

```
████████╗██╗  ██╗ ██████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
╚══██╔══╝██║  ██║██╔═████╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
   ██║   ███████║██║██╔██║██████╔╝███████╗██║     ███████║██╔██╗ ██║
   ██║   ██╔══██║████╔╝██║██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
   ██║   ██║  ██║╚██████╔╝██║  ██║███████║╚██████╗██║  ██║██║ ╚████║
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

              >> BRUTAL SECURITY SCANNER <<
           v1.0.0  |  by Thorranov  |  Cyber Intelligence
```

## 🔧 Development

```bash
# Clone repo
git clone https://github.com/thorranov/th0rsc4n.git
cd th0rsc4n

# Buat virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install dalam mode development
pip install -e .

# Test
th0rsc4n --help
```

## 📄 License

MIT © [Thorranov](https://github.com/thorranov)

## ⚠️ Disclaimer

Tool ini dibuat untuk **tujuan edukasi dan security testing yang sah**. Jangan gunakan untuk menyerang sistem tanpa izin tertulis. Penulis tidak bertanggung jawab atas penyalahgunaan.
