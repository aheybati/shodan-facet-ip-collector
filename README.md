# 🔍 Shodan Facet IP Collector — aheybati Scanner v3.1

**Extract IP addresses from Shodan without API credits — using facet pages with smart sub-querying.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🎯 What Does It Do?

This tool logs into your **free Shodan account** and collects IP addresses by crawling Shodan's **facet pages** instead of using the paid API. Since facets are part of the regular web interface, **no query credits are consumed**.

| Query Example | Total on Shodan | Estimated Coverage |
|---|---|---|
| SSH (`port:"22"`) | ~18.4M | **~90-95%** |
| Apache (`port:"80" product:"Apache"`) | ~50M+ | **~85-92%** |
| MySQL (`port:"3306" product:"MySQL"`) | ~5M+ | **~88-94%** |
| Redis (`port:"6379" product:"Redis"`) | ~1M+ | **~92-97%** |

### Key Features

| Feature | Description |
|---|---|
| 🔄 **Multi-level sub-query** | Automatically drills down: country → city → org → net when any level hits the 1000-result cap |
| 🔌 **IP:PORT output** | `--with-ports` mode extracts port numbers alongside IPs |
| 💾 **Incremental save** | Results are written to file immediately as they're found — no data lost on crash |
| 📂 **Resume** | `--resume` continues from where you left off, skipping completed countries/cities/orgs |
| 🚫 **Country exclude** | `--exclude IR,US` filters out unwanted countries |
| 🔐 **Auto re-login** | Detects expired Shodan sessions and re-authenticates automatically |
| 🔁 **Retry logic** | FlareSolverr requests retry up to 3 times with progressive backoff |
| 🛑 **Graceful Ctrl+C** | Interrupting saves progress — just `--resume` later |
| 🔑 **3 credential methods** | Command line, environment variables, or `.env` file |

---

## ⚡ Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs `requests`, `beautifulsoup4`, and `python-dotenv`.

### 2. Install FlareSolverr (Required)

Shodan uses Cloudflare protection. FlareSolverr bypasses it automatically.

**Easy way (installs Docker + FlareSolverr):**

```bash
chmod +x install_flaresolverr.sh
sudo ./install_flaresolverr.sh
```

**Manual way (if you already have Docker):**

```bash
docker run -d \
    --name=flaresolverr \
    -p 8191:8191 \
    -e LOG_LEVEL=info \
    -e LOG_HTML=false \
    -e CAPTCHA_SOLVER=none \
    --restart unless-stopped \
    ghcr.io/flaresolverr/flaresolverr:latest
```

> **FlareSolverr Source:** [github.com/FlareSolverr/FlareSolverr](https://github.com/FlareSolverr/FlareSolverr)
> 
> FlareSolverr is an open-source proxy server that solves Cloudflare challenges. It runs a headless browser to bypass Cloudflare's anti-bot protection.

### 3. Configure Credentials

You can provide your Shodan credentials in **three ways**:

**Option A — Command line:**
```bash
python3 shodan_facet_collector.py -u user@email.com -p mypass -q 'port:"22"'
```

**Option B — Environment variables:**
```bash
export SHODAN_USERNAME=user@email.com
export SHODAN_PASSWORD=mypass
python3 shodan_facet_collector.py -q 'port:"22"'
```

**Option C — `.env` file (recommended for persistence):**
```bash
cp .env.example .env
# Edit .env with your credentials:
#   SHODAN_USERNAME=user@email.com
#   SHODAN_PASSWORD=mypass
python3 shodan_facet_collector.py -q 'port:"22"'
```

> ⚠️ The `.env` file is listed in `.gitignore` and will **never** be committed to git.

### 4. Run the Scanner

```bash
python3 shodan_facet_collector.py -u YOUR_EMAIL -p YOUR_PASSWORD -q 'port:"22"'
```

---

## 📖 Usage

```
usage: shodan_facet_collector.py [-h] [-u USERNAME] [-p PASSWORD] -q QUERY
                                 [-x EXCLUDE] [-o OUTPUT] [-d DELAY] [-w] [--resume]

Shodan Facet IP Collector — Abbas Scanner v2.3

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Shodan username/email (or set SHODAN_USERNAME env var)
  -p PASSWORD, --password PASSWORD
                        Shodan password (or set SHODAN_PASSWORD env var)
  -q QUERY, --query QUERY
                        Shodan query string
  -x EXCLUDE, --exclude EXCLUDE
                        Country codes to EXCLUDE (e.g. IR,US)
  -o OUTPUT, --output OUTPUT
                        Output file (default: ips.txt or ips_ports.txt)
  -d DELAY, --delay DELAY
                        Delay between requests in seconds (default: 3)
  -w, --with-ports      Include port numbers in output (IP:PORT format)
  --resume              Resume from previous progress
```

### Examples

**SSH servers on port 22:**
```bash
python3 shodan_facet_collector.py -u user@email.com -p mypass -q 'port:"22"'
```

**Exclude Countries:**
```bash
python3 shodan_facet_collector.py -u user@email.com -p mypass -q 'port:"22"' --exclude IR,US
```

**Apache web servers:**
```bash
python3 shodan_facet_collector.py -u user@email.com -p mypass -q 'port:"80" product:"Apache"'
```

**MySQL databases:**
```bash
python3 shodan_facet_collector.py -u user@email.com -p mypass -q 'port:"3306" product:"MySQL"'
```

**Include port numbers in output (IP:PORT format):**
```bash
python3 shodan_facet_collector.py -u user@email.com -p mypass -q 'product:"nginx"' --with-ports
```

**With ports + exclude countries:**
```bash
python3 shodan_facet_collector.py -u user@email.com -p mypass -q 'product:"nginx"' --with-ports --exclude IR,US
```

**Custom output file and faster delay:**
```bash
python3 shodan_facet_collector.py -u user@email.com -p mypass -q 'port:"80" product:"Apache"' -o apache_ips.txt -d 2
```

**Resume a crashed/interrupted scan:**
```bash
python3 shodan_facet_collector.py -u user@email.com -p mypass -q 'port:"22"' --resume
```

**Using .env file (no credentials on command line):**
```bash
python3 shodan_facet_collector.py -q 'port:"22"'
```

---


### Output Files

| File | Description |
|---|---|
| `ips.txt` | Collected unique IP addresses (one per line) |
| `ips_ports.txt` | IP addresses with port numbers (one IP:PORT per line) — created with `--with-ports` |
| `progress.json` | Resume state — enables `--resume` after interruptions |

### Output Format Examples

**Without `--with-ports` (default):**
```
192.168.1.1
192.168.1.2
192.168.1.5
```

**With `--with-ports`:**
```
192.168.1.1:80
192.168.1.1:443
192.168.1.2:22
192.168.1.5:8080
```

Final summary:
```
🏁 ALL DONE!
📊 Total IP:PORT entries collected: 50000
🌍 Countries scanned: 123
🏙️ Cities scanned: 4250
📁 Saved to: list-ip-port.txt or list-ip.txt
```

---

## 🔐 Security

- Your Shodan credentials are sent directly to Shodan's login page (HTTPS).
- **No credentials are stored** in any file or sent to any third-party server.
- `.env` file is excluded from git via `.gitignore` — your credentials stay local.
- A **free Shodan account** is all you need — no paid membership required.
- This tool does **not** consume any Shodan API credits.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security research and educational purposes only**. The authors are not responsible for any misuse. Always ensure you comply with Shodan's Terms of Service and applicable laws.

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

**Author:** Abbas Heybati
