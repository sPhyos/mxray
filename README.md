# MXRAY – Mail & Web Recon Engine

**MXRAY** is a Bash-based recon tool for quickly assessing email and web security posture of a domain:

- MX / DNS / PTR checks
- SPF / DMARC / DKIM analysis
- SMTP banner + STARTTLS + TLS version checks (`--aggressive`)
- Basic subdomain & subdomain-takeover heuristics
- Webmail / HTTP security header checks (HSTS, CSP, X-Frame-Options)
- WAF / CDN fingerprinting (Cloudflare, Sucuri, Imperva, CloudFront, Akamai, …)
- Risk score + severity breakdown
- Optional report output to file

> Ideal for: bug bounty, pentest recon, blue-team audits, CentiSec Academy labs, etc.

---

## Installation

Just clone the repo and make the script executable:

```bash
git clone https://github.com/sPhyos/mxray.git
cd mxray
chmod +x mxray.sh
```
