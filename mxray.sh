#!/usr/bin/env bash
# Enhanced Mail Security Scanner with External Services Integration
# Version: 7.0 - Mail & Webmail Recon + WAF Detection + Risk Scoring

set -e

RED="\033[31m"
YELLOW="\033[33m"
GREEN="\033[32m"
BLUE="\033[34m"
MAGENTA="\033[35m"
CYAN="\033[36m"
BOLD="\033[1m"
RESET="\033[0m"

CRITICAL="[CRITICAL]"
HIGH="[HIGH]"
MEDIUM="[MEDIUM]"
LOW="[LOW]"
INFO="[INFO]"

domain=""
use_external=true
aggressive_scan=false
output_file=""
vulnerabilities=()
vuln_count=0
risk_score=0
start_time=$(date +%s)

while [[ $# -gt 0 ]]; do
    case $1 in
        --aggressive) aggressive_scan=true; shift ;;
        --no-external) use_external=false; shift ;;
        --output) output_file="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 <domain> [OPTIONS]"
            echo "Options:"
            echo "  --aggressive    Enable active SMTP/STARTTLS testing"
            echo "  --no-external   Disable external API calls"
            echo "  --output FILE   Save report to file"
            exit 0
            ;;
        *) domain="$1"; shift ;;
    esac
done

if [ -z "$domain" ]; then
    read -rp "Target domain: " domain
    [ -z "$domain" ] && { echo "Domain required!"; exit 1; }
fi

domain=$(echo "$domain" | sed 's|^https\?://||' | sed 's|/$||')

if [ -n "$output_file" ]; then
    : > "$output_file"
fi

log_output() {
    echo -e "$1"
    if [ -n "$output_file" ]; then
        # strip color codes for file output
        echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$output_file"
    fi
}

add_vuln() {
    local severity="$1"
    local title="$2"
    local description="$3"
    local remediation="$4"

    vuln_count=$((vuln_count + 1))
    vulnerabilities+=("$severity|$title|$description|$remediation")

    # Simple risk scoring model
    case "$severity" in
        "$CRITICAL") risk_score=$((risk_score + 40)) ;;
        "$HIGH")     risk_score=$((risk_score + 20)) ;;
        "$MEDIUM")   risk_score=$((risk_score + 10)) ;;
        "$LOW")      risk_score=$((risk_score + 5))  ;;
    esac
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

log_output "${BOLD}${BLUE}╔════════════════════════════════════════════════════════════════╗${RESET}"
log_output "${BOLD}${BLUE}║        ENHANCED MAIL SECURITY SCANNER v7.0                     ║${RESET}"
log_output "${BOLD}${BLUE}║        Target: $domain${RESET}"
log_output "${BOLD}${BLUE}║        Aggressive: $aggressive_scan | External: $use_external  ${RESET}"
log_output "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════════╝${RESET}"
log_output ""

# ============================================================
# [1] DNS & MX Records
# ============================================================
log_output "${BOLD}${CYAN}[1] DNS & MX Records${RESET}"
log_output "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

mx_hosts=()
mx_list=$(dig +short MX "$domain" 2>/dev/null)
mx_count=$(echo "$mx_list" | sed '/^$/d' | wc -l)

if [ "$mx_count" -eq 0 ]; then
    log_output "${RED}${CRITICAL} No MX records${RESET}"
    add_vuln "$CRITICAL" "Missing MX" "Domain cannot receive email" "Add valid MX records pointing to your mail servers"
else
    log_output "${GREEN}✓ MX Records ($mx_count):${RESET}"
    while read -r pref host; do
        [ -z "$host" ] && continue
        mx_hosts+=("$host")
        log_output "  $pref $host"
    done <<< "$mx_list"
fi

log_output ""

# ---- MX IP / PTR checks ----
if [ "${#mx_hosts[@]}" -gt 0 ]; then
    log_output "${BOLD}${CYAN}  MX IP / PTR checks${RESET}"

    for mx in "${mx_hosts[@]}"; do
        mx_clean="${mx%.}" # remove trailing dot

        ips=$(dig +short A "$mx_clean" 2>/dev/null)
        if [ -z "$ips" ]; then
            log_output "  ${YELLOW}${HIGH} $mx_clean has no A record (only MX)${RESET}"
            add_vuln "$HIGH" "MX without A record" \
                     "Mail exchanger $mx_clean has no A record" \
                     "Ensure MX hostname has a valid A record pointing to the mail server IP"
            continue
        fi

        while read -r ip; do
            [ -z "$ip" ] && continue
            ptr=$(dig +short -x "$ip" 2>/dev/null)
            if [ -z "$ptr" ]; then
                log_output "  ${YELLOW}${LOW} $mx_clean ($ip) has no PTR record${RESET}"
                add_vuln "$LOW" "Missing PTR for MX IP" \
                         "No reverse DNS (PTR) record exists for $ip" \
                         "Add PTR record that points back to $mx_clean to improve mail reputation"
            else
                log_output "  ${GREEN}✓ $mx_clean ($ip) -> PTR: $ptr${RESET}"
            fi
        done <<< "$ips"
    done

    log_output ""
fi

# ---- Aggressive SMTP / STARTTLS tests ----
if [ "$aggressive_scan" = true ] && [ "${#mx_hosts[@]}" -gt 0 ]; then
    log_output "${BOLD}${CYAN}  Aggressive SMTP / STARTTLS tests${RESET}"

    if ! check_command timeout; then
        log_output "  ${YELLOW}timeout not found – tests may hang on unresponsive hosts${RESET}"
    fi

    for mx in "${mx_hosts[@]}"; do
        mx_clean="${mx%.}"

        # SMTP banner via nc
        if check_command nc; then
            banner=$(echo -e "QUIT\r\n" | timeout 5 nc -w 3 "$mx_clean" 25 2>/dev/null | head -n1 || true)
            if [ -n "$banner" ]; then
                log_output "  ${GREEN}✓ SMTP banner from $mx_clean: $banner${RESET}"
            else
                log_output "  ${YELLOW}${MEDIUM} No visible SMTP banner from $mx_clean:25${RESET}"
                add_vuln "$MEDIUM" "No SMTP banner" \
                         "Cannot read SMTP banner from $mx_clean:25" \
                         "Verify SMTP service is reachable and not blocked by firewalls"
            fi
        else
            log_output "  ${YELLOW}nc not installed – skipping banner check for $mx_clean${RESET}"
        fi

        # STARTTLS via openssl (with TLS version analysis)
        if check_command openssl; then
            starttls_full=$(echo -e "QUIT\r\n" | timeout 7 \
                openssl s_client -starttls smtp -connect "$mx_clean:25" -servername "$domain" 2>/dev/null || true)

            verify_line=$(echo "$starttls_full" | grep -i "Verify return code" | head -n1)
            proto_line=$(echo "$starttls_full"  | grep -i "Protocol"          | head -n1)
            proto=$(echo "$proto_line" | awk -F':' '{if (NF>1){gsub(/^[ \t]+/,"",$2); print $2}}')

            if echo "$verify_line" | grep -q "0 (ok)"; then
                log_output "  ${GREEN}✓ STARTTLS valid for $mx_clean (${verify_line:-no verify line})${RESET}"
            elif [ -n "$verify_line" ]; then
                log_output "  ${YELLOW}${MEDIUM} STARTTLS issues on $mx_clean: $verify_line${RESET}"
                add_vuln "$MEDIUM" "Weak STARTTLS" \
                         "TLS handshake not clean on $mx_clean (verify return code not 0)" \
                         "Fix certificate chain, hostname mismatch, and TLS settings on SMTP server"
            else
                log_output "  ${YELLOW}${HIGH} No STARTTLS detected on $mx_clean${RESET}"
                add_vuln "$HIGH" "No STARTTLS on MX" \
                         "Mail exchanger $mx_clean does not appear to support STARTTLS" \
                         "Enable STARTTLS with a valid certificate to protect SMTP traffic"
            fi

            if [ -n "$proto" ]; then
                case "$proto" in
                    TLSv1|TLSv1.1)
                        log_output "  ${YELLOW}${HIGH} Legacy TLS version in use: $proto${RESET}"
                        add_vuln "$HIGH" "Legacy TLS on SMTP" \
                                 "SMTP STARTTLS negotiates $proto on $mx_clean" \
                                 "Disable TLS 1.0/1.1 and enforce modern protocols (TLS 1.2+)"
                        ;;
                    TLSv1.2)
                        log_output "  ${GREEN}  Protocol in use: TLS 1.2${RESET}"
                        ;;
                    TLSv1.3)
                        log_output "  ${GREEN}  Protocol in use: TLS 1.3${RESET}"
                        ;;
                esac
            fi
        else
            log_output "  ${YELLOW}openssl not installed – skipping STARTTLS check for $mx_clean${RESET}"
        fi
    done

    log_output ""
fi

# ============================================================
# [2] SPF Check
# ============================================================
log_output "${BOLD}${CYAN}[2] SPF Check${RESET}"
log_output "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

spf=$(dig +short TXT "$domain" 2>/dev/null | grep "v=spf1" | tr -d '"')

if [ -z "$spf" ]; then
    log_output "${RED}${CRITICAL} SPF: NOT FOUND${RESET}"
    add_vuln "$CRITICAL" "Missing SPF" "Domain has no SPF record, making spoofing easier" \
             "Add an SPF TXT record (e.g., v=spf1 mx -all) to define authorized senders"
else
    log_output "${GREEN}✓ SPF: $spf${RESET}"
    
    if echo "$spf" | grep -q "+all"; then
        log_output "${RED}${CRITICAL} Dangerous +all policy${RESET}"
        add_vuln "$CRITICAL" "SPF +all" \
                 "SPF allows any sender (includes +all)" \
                 "Replace +all with -all and correctly define authorized senders"
    elif echo "$spf" | grep -q "~all"; then
        log_output "${YELLOW}${LOW} Soft fail ~all${RESET}"
        add_vuln "$LOW" "SPF soft fail (~all)" \
                 "SPF uses soft fail (~all), spoofed mail may still be accepted" \
                 "Consider switching to -all after testing to enforce strict policy"
    elif echo "$spf" | grep -q "\-all"; then
        log_output "${GREEN}✓ Hard fail -all${RESET}"
    fi

    # Approximate check: very long SPF might cause issues
    if [ "${#spf}" -gt 450 ]; then
        log_output "${YELLOW}${LOW} SPF record is quite long (${#spf} chars) – risk of hitting DNS limits${RESET}"
        add_vuln "$LOW" "Long SPF record" \
                 "SPF has length ${#spf} characters" \
                 "Flatten or simplify SPF to avoid DNS lookup and size limits"
    fi

    # Rough DNS lookup count (SPF limit = 10)
    lookup_count=$(echo "$spf" | grep -oE "(include:|a|mx|ptr|exists:|redirect=)" | wc -l)
    if [ "$lookup_count" -ge 8 ]; then
        log_output "${YELLOW}${LOW} SPF uses ~$lookup_count DNS mechanisms – close to 10-query limit${RESET}"
        add_vuln "$LOW" "SPF near DNS lookup limit" \
                 "SPF appears to cause about $lookup_count DNS lookups" \
                 "Reduce include/redirect mechanisms to stay comfortably under 10"
    fi
fi

log_output ""

# ============================================================
# [3] DMARC Check
# ============================================================
log_output "${BOLD}${CYAN}[3] DMARC Check${RESET}"
log_output "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

dmarc=$(dig +short TXT "_dmarc.$domain" 2>/dev/null | tr -d '"')

if [ -z "$dmarc" ]; then
    log_output "${RED}${CRITICAL} DMARC: NOT FOUND${RESET}"
    add_vuln "$CRITICAL" "Missing DMARC" \
             "Domain has no DMARC policy, spoofed emails may not be handled" \
             "Add a DMARC TXT record (start with p=none for monitoring, then move to p=quarantine/reject)"
else
    log_output "${GREEN}✓ DMARC: $dmarc${RESET}"
    
    if echo "$dmarc" | grep -q "p=none"; then
        log_output "${YELLOW}${MEDIUM} Policy: none (monitoring only)${RESET}"
        add_vuln "$MEDIUM" "DMARC not enforced" \
                 "DMARC policy is p=none, only monitoring" \
                 "After fixing alignment, switch to p=quarantine or p=reject"
    elif echo "$dmarc" | grep -q "p=reject"; then
        log_output "${GREEN}✓ Policy: reject${RESET}"
    elif echo "$dmarc" | grep -q "p=quarantine"; then
        log_output "${GREEN}✓ Policy: quarantine${RESET}"
    fi

    # Check for aggregate reporting
    if ! echo "$dmarc" | grep -q "rua="; then
        log_output "${YELLOW}${LOW} No DMARC aggregate report address (rua) configured${RESET}"
        add_vuln "$LOW" "No DMARC rua" \
                 "DMARC aggregate reports are not sent anywhere" \
                 "Add rua=mailto:security@yourdomain to DMARC to receive reports"
    fi

    # Check percentage if set
    pct_val=$(echo "$dmarc" | sed -n 's/.*pct=\([0-9]\+\).*/\1/p')
    if [ -n "$pct_val" ] && [ "$pct_val" -lt 100 ]; then
        log_output "${YELLOW}${MEDIUM} DMARC policy applies only to $pct_val% of mail${RESET}"
        add_vuln "$MEDIUM" "Partial DMARC enforcement" \
                 "DMARC pct=$pct_val – policy enforced only on part of traffic" \
                 "Increase pct to 100 once you are confident in DMARC settings"
    fi
fi

log_output ""

# ============================================================
# [4] DKIM Check
# ============================================================
log_output "${BOLD}${CYAN}[4] DKIM Check${RESET}"
log_output "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

selectors=(default mail google s1 s2 selector1 selector2 dkim k1 yandex)
dkim_found=false

for sel in "${selectors[@]}"; do
    dkim=$(dig +short TXT "${sel}._domainkey.$domain" 2>/dev/null | tr -d '"')
    if [ -n "$dkim" ]; then
        log_output "${GREEN}✓ DKIM selector: $sel${RESET}"
        dkim_found=true
        
        key_len=$(echo "$dkim" | grep -oE 'p=[A-Za-z0-9+/=]+' | wc -c)
        if [ "$key_len" -lt 300 ]; then
            log_output "  ${RED}${HIGH} Weak DKIM key (likely 1024-bit)${RESET}"
            add_vuln "$HIGH" "Weak DKIM key" \
                     "DKIM key for selector $sel is likely 1024-bit" \
                     "Rotate DKIM keys to at least 2048-bit RSA"
        fi
    fi
done

if [ "$dkim_found" = false ]; then
    log_output "${YELLOW}${HIGH} No common DKIM selectors found (may still exist under custom selector)${RESET}"
    add_vuln "$HIGH" "DKIM not detected on common selectors" \
             "No DKIM keys on standard selectors" \
             "Verify DKIM is configured and published under correct selectors"
fi

log_output ""

# ============================================================
# [5] External Service Checks
# ============================================================
if [ "$use_external" = true ] && check_command curl; then
    log_output "${BOLD}${CYAN}[5] External Security Services${RESET}"
    log_output "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    
    # MXToolbox Check (basic)
    log_output "${BLUE}[MXToolbox] Checking DNS health...${RESET}"
    mxtoolbox=$(curl -s "https://mxtoolbox.com/Public/Tools/BulkLookup.aspx/GetDnsHealthReportResult?domain=$domain" --max-time 10 2>/dev/null || echo "timeout")
    
    if [ "$mxtoolbox" != "timeout" ]; then
        if echo "$mxtoolbox" | grep -qi "blacklist"; then
            log_output "  ${YELLOW}⚠ MXToolbox indicates potential blacklist hits – check manually${RESET}"
        fi
        log_output "  ${GREEN}✓ MXToolbox scan completed (review details in browser if needed)${RESET}"
    else
        log_output "  ${YELLOW}⚠ MXToolbox request timeout${RESET}"
    fi
    
    # DNS Dumpster style subdomain check without API
    log_output ""
    log_output "${BLUE}[DNSDumpster] Basic subdomain enumeration...${RESET}"
    
    common_subs=(www mail smtp pop imap webmail ftp admin cpanel dev staging test api mobile)
    found_subs=0
    
    for sub in "${common_subs[@]}"; do
        result=$(dig +short A "${sub}.$domain" 2>/dev/null)
        if [ -n "$result" ]; then
            log_output "  ${GREEN}✓ ${sub}.$domain -> $result${RESET}"
            found_subs=$((found_subs + 1))
        fi
    done
    
    log_output "  Found $found_subs common subdomains"
    
    # SSL Labs check (just info)
    log_output ""
    log_output "${BLUE}[SSL Labs] Check manually at:${RESET}"
    log_output "  https://www.ssllabs.com/ssltest/analyze.html?d=$domain"
    
    # SecurityTrails info
    log_output ""
    log_output "${BLUE}[SecurityTrails] Historical DNS:${RESET}"
    log_output "  https://securitytrails.com/domain/$domain/dns"
    
    log_output ""
fi

# ============================================================
# [6] Subdomain Takeover Detection
# ============================================================
log_output "${BOLD}${CYAN}[6] Subdomain Takeover Detection${RESET}"
log_output "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

all_subs=(mail smtp www dev staging test prod api admin portal blog shop store
          app mobile web ftp vpn cloud backup support help docs wiki git
          az en ru us uk de fr es it tr ar jp cn kr)

takeover_found=false

for sub in "${all_subs[@]}"; do
    cname=$(dig +short CNAME "${sub}.$domain" 2>/dev/null | sed 's/\.$//')
    
    if [ -n "$cname" ]; then
        ip=$(dig +short A "$cname" 2>/dev/null)
        
        if [ -z "$ip" ]; then
            log_output "${RED}⚠ ${sub}.$domain -> $cname (NO IP!)${RESET}"
            
            # Check for known vulnerable services
            if echo "$cname" | grep -qE "(herokuapp|github\.io|azurewebsites|shopify|zendesk|ghost\.io|bitbucket\.io|s3\.amazonaws|pantheonsite)"; then
                log_output "  ${RED}${CRITICAL} SUBDOMAIN TAKEOVER LIKELY!${RESET}"
                log_output "  Service: $(echo "$cname" | grep -oE '[^.]+\.(herokuapp|github\.io|azurewebsites|shopify|zendesk|ghost\.io|bitbucket\.io|amazonaws|pantheonsite)' | tail -1)"
                
                takeover_found=true
                add_vuln "$CRITICAL" "Subdomain Takeover: ${sub}.$domain" \
                    "Points to unclaimed or dangling service: $cname" \
                    "Either claim the service or remove the CNAME record"
                
                # HTTP check for confirmation
                if check_command curl; then
                    http_resp=$(curl -sL -w "%{http_code}" -o /dev/null --max-time 5 "http://${sub}.$domain" 2>/dev/null || echo "000")
                    log_output "  HTTP Status: $http_resp"
                    
                    if [ "$http_resp" = "404" ]; then
                        page_content=$(curl -sL --max-time 5 "http://${sub}.$domain" 2>/dev/null | head -20)
                        if echo "$page_content" | grep -qiE "(not found|no such app|does not exist)"; then
                            log_output "  ${RED}✓ Confirmed: Service shows 'not found' style error${RESET}"
                        fi
                    fi
                fi
            else
                log_output "  ${YELLOW}${HIGH} Dangling CNAME (manual check needed)${RESET}"
                add_vuln "$HIGH" "Dangling CNAME: ${sub}.$domain" \
                    "CNAME $cname does not resolve to an IP" \
                    "Investigate and remove if unused or misconfigured"
            fi
            log_output ""
        fi
    fi
done

if [ "$takeover_found" = true ]; then
    log_output "${RED}${BOLD}⚠️ SUBDOMAIN TAKEOVER VULNERABILITIES FOUND!${RESET}"
else
    log_output "${GREEN}✓ No obvious subdomain takeovers detected${RESET}"
fi

log_output ""

# ============================================================
# [7] OSINT & Threat Intelligence
# ============================================================
log_output "${BOLD}${CYAN}[7] OSINT & Threat Intelligence${RESET}"
log_output "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

log_output "${BLUE}Manual checks recommended:${RESET}"
log_output ""
log_output "📧 Email Security:"
log_output "  • https://mxtoolbox.com/domain/$domain"
log_output "  • https://dmarcian.com/domain-checker/"
log_output "  • https://emailsecuritygrader.com/"
log_output ""
log_output "🔍 Subdomain Discovery:"
log_output "  • https://dnsdumpster.com/"
log_output "  • https://crt.sh/?q=%.$domain"
log_output "  • https://securitytrails.com/domain/$domain"
log_output ""
log_output "🛡️ Security Scanning:"
log_output "  • https://www.ssllabs.com/ssltest/analyze.html?d=$domain"
log_output "  • https://observatory.mozilla.org/analyze/$domain"
log_output "  • https://www.immuniweb.com/ssl/"
log_output ""
log_output "📊 Threat Intelligence:"
log_output "  • https://www.virustotal.com/gui/domain/$domain"
log_output "  • https://urlscan.io/search/#domain:$domain"
log_output "  • https://otx.alienvault.com/browse/global/pulses?q=$domain"

log_output ""

# ============================================================
# [8] Webmail & HTTP Security Headers
# ============================================================
log_output "${BOLD}${CYAN}[8] Webmail & HTTP Security Headers${RESET}"
log_output "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

if ! check_command curl; then
    log_output "${YELLOW}curl not installed – skipping HTTP header analysis${RESET}"
else
    web_targets=()
    # Likely webmail / login hosts
    web_targets+=("webmail.$domain")
    web_targets+=("mail.$domain")
    web_targets+=("$domain")

    checked=()

    for host in "${web_targets[@]}"; do
        # avoid duplicate hosts
        skip=false
        for seen in "${checked[@]}"; do
            if [ "$seen" = "$host" ]; then
                skip=true
                break
            fi
        done
        if [ "$skip" = true ]; then
            continue
        fi
        checked+=("$host")

        # Try HTTPS first, fallback to HTTP
        url="https://$host"
        code=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" || echo "000")

        if [ "$code" = "000" ] || [ "$code" = "0000" ]; then
            url="http://$host"
            code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" || echo "000")
        fi

        if [ "$code" = "000" ]; then
            log_output "  ${YELLOW}No HTTP response from $host (skipping)${RESET}"
            continue
        fi

        log_output "  ${GREEN}Checked $url (HTTP $code)${RESET}"

        # Fetch headers
        headers=$(curl -k -s -D - -o /dev/null --max-time 7 "$url" 2>/dev/null || true)

        has_hsts=false
        has_csp=false
        has_xfo=false

        if echo "$headers" | grep -qi '^Strict-Transport-Security:'; then
            has_hsts=true
            log_output "    ${GREEN}✓ HSTS enabled${RESET}"
        fi

        if echo "$headers" | grep -qi '^Content-Security-Policy:'; then
            has_csp=true
            log_output "    ${GREEN}✓ Content-Security-Policy present${RESET}"
        fi

        if echo "$headers" | grep -qi '^X-Frame-Options:'; then
            has_xfo=true
            log_output "    ${GREEN}✓ X-Frame-Options present${RESET}"
        fi

        if [ "$has_hsts" = false ]; then
            log_output "    ${YELLOW}${MEDIUM} Missing HSTS header – susceptible to SSL stripping${RESET}"
            add_vuln "$MEDIUM" "Missing HSTS on $host" \
                     "Strict-Transport-Security header not set" \
                     "Enable HSTS with an appropriate max-age and includeSubDomains (if safe)"
        fi

        if [ "$has_csp" = false ]; then
            log_output "    ${YELLOW}${LOW} Missing CSP header – higher XSS risk${RESET}"
            add_vuln "$LOW" "Missing CSP on $host" \
                     "Content-Security-Policy header not present" \
                     "Define a CSP to restrict script sources and reduce XSS impact"
        fi

        if [ "$has_xfo" = false ]; then
            log_output "    ${YELLOW}${LOW} Missing X-Frame-Options – clickjacking risk${RESET}"
            add_vuln "$LOW" "Missing X-Frame-Options on $host" \
                     "Site may be embeddable in iframes" \
                     "Set X-Frame-Options or frame-ancestors in CSP to prevent clickjacking"
        fi

        log_output ""
    done
fi

log_output ""

# ============================================================
# [9] Recommended Scanning Tools
# ============================================================
log_output "${BOLD}${CYAN}[9] Recommended Scanning Tools${RESET}"
log_output "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

log_output "${YELLOW}Install and run these tools for deeper analysis:${RESET}"
log_output ""
log_output "1. Subfinder (subdomain enumeration):"
log_output "   ${BLUE}subfinder -d $domain -o subdomains.txt${RESET}"
log_output ""
log_output "2. Nuclei (vulnerability scanning):"
log_output "   ${BLUE}nuclei -u https://$domain -t dns/ -t takeovers/${RESET}"
log_output ""
log_output "3. Subzy (subdomain takeover):"
log_output "   ${BLUE}subzy run --targets $domain${RESET}"
log_output ""
log_output "4. Amass (comprehensive DNS enum):"
log_output "   ${BLUE}amass enum -d $domain${RESET}"
log_output ""
log_output "5. DNSRecon:"
log_output "   ${BLUE}dnsrecon -d $domain${RESET}"
log_output ""
log_output "6. TheHarvester:"
log_output "   ${BLUE}theharvester -d $domain -b all${RESET}"

log_output ""

# ============================================================
# [10] WAF / CDN Detection
# ============================================================
log_output "${BOLD}${CYAN}[10] WAF / CDN Detection${RESET}"
log_output "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

if ! check_command curl; then
    log_output "${YELLOW}curl not installed – skipping WAF detection${RESET}"
else
    waf_url="https://$domain"
    tmp_body="/tmp/mailscan_waf_body.$$"

    # Grab headers + first part of body
    waf_headers=$(curl -k -s -D - -o "$tmp_body" --max-time 10 "$waf_url" 2>/dev/null || true)
    waf_code=$(echo "$waf_headers" | head -n1 | awk '{print $2}')
    waf_body_head=$(head -n 40 "$tmp_body" 2>/dev/null || true)
    rm -f "$tmp_body" 2>/dev/null || true

    # If HTTPS totally fails, try HTTP
    if [ -z "$waf_headers" ]; then
        waf_url="http://$domain"
        tmp_body="/tmp/mailscan_waf_body.$$"
        waf_headers=$(curl -s -D - -o "$tmp_body" --max-time 10 "$waf_url" 2>/dev/null || true)
        waf_code=$(echo "$waf_headers" | head -n1 | awk '{print $2}')
        waf_body_head=$(head -n 40 "$tmp_body" 2>/dev/null || true)
        rm -f "$tmp_body" 2>/dev/null || true
    fi

    if [ -z "$waf_headers" ]; then
        log_output "${YELLOW}No HTTP response from $domain – cannot detect WAF/CDN${RESET}"
    else
        log_output "  Checked: $waf_url (HTTP ${waf_code:-unknown})"

        waf_vendor="Unknown / Not obvious"

        # Cloudflare
        if echo "$waf_headers" | grep -qi "cloudflare" || \
           echo "$waf_headers" | grep -qi "cf-ray:" || \
           echo "$waf_headers" | grep -qi "cf-cache-status:"; then
            waf_vendor="Cloudflare"
        # Sucuri
        elif echo "$waf_headers" | grep -qi "sucuri" || \
             echo "$waf_headers" | grep -qi "x-sucuri-id"; then
            waf_vendor="Sucuri"
        # Imperva / Incapsula
        elif echo "$waf_headers" | grep -qi "incapsula" || \
             echo "$waf_headers" | grep -qi "x-cdn: incapsula"; then
            waf_vendor="Imperva Incapsula"
        # AWS CloudFront / AWS WAF
        elif echo "$waf_headers" | grep -qi "cloudfront" || \
             echo "$waf_headers" | grep -qi "x-amz-cf-id" || \
             echo "$waf_headers" | grep -qi "x-amz-cf-pop"; then
            waf_vendor="AWS CloudFront / AWS WAF"
        # Akamai
        elif echo "$waf_headers" | grep -qi "akamai" || \
             echo "$waf_headers" | grep -qi "x-akamai"; then
            waf_vendor="Akamai"
        # F5 BIG-IP (very rough heuristics)
        elif echo "$waf_headers" | grep -qi "bigip" || \
             echo "$waf_headers" | grep -qi "x-waf" || \
             echo "$waf_headers" | grep -qi "x-aspnet-version" && echo "$waf_headers" | grep -qi "f5"; then
            waf_vendor="F5 BIG-IP (heuristic)"
        # Generic WAF hints in body
        elif echo "$waf_body_head" | grep -qi "access denied" && \
             echo "$waf_body_head" | grep -qi "security policy"; then
            waf_vendor="Possible generic WAF (Access Denied page)"
        fi

        if [ "$waf_vendor" = "Unknown / Not obvious" ]; then
            log_output "  ${YELLOW}No obvious WAF/CDN fingerprints detected${RESET}"
            # Not necessarily a vuln, just info. If you want, you can treat "no WAF" as LOW here.
        else
            log_output "  ${GREEN}Detected WAF/CDN: ${waf_vendor}${RESET}"
        fi
    fi
fi

log_output ""

# ============================================================
# VULNERABILITY SUMMARY
# ============================================================
log_output "${BOLD}${MAGENTA}╔════════════════════════════════════════════════════════════════╗${RESET}"
log_output "${BOLD}${MAGENTA}║                  VULNERABILITY SUMMARY                         ║${RESET}"
log_output "${BOLD}${MAGENTA}╚════════════════════════════════════════════════════════════════╝${RESET}"
log_output ""

if [ "$vuln_count" -eq 0 ]; then
    log_output "${GREEN}${BOLD}✓ No critical findings in this basic scan${RESET}"
    log_output "${YELLOW}ℹ Run the recommended external tools above for comprehensive testing${RESET}"
else
    log_output "${RED}${BOLD}Found $vuln_count issues:${RESET}"
    log_output ""
    
    critical_count=0
    high_count=0
    medium_count=0
    low_count=0
    
    for vuln in "${vulnerabilities[@]}"; do
        IFS='|' read -r severity title description remediation <<< "$vuln"
        
        case $severity in
            "$CRITICAL") ((critical_count++)); color=$RED ;;
            "$HIGH")     ((high_count++)); color=$RED ;;
            "$MEDIUM")   ((medium_count++)); color=$YELLOW ;;
            "$LOW")      ((low_count++)); color=$YELLOW ;;
            *)           color=$RESET ;;
        esac
        
        log_output "${color}${severity} ${title}${RESET}"
        log_output "  Issue: $description"
        log_output "  Fix:   $remediation"
        log_output ""
    done
    
    log_output "${BOLD}Severity Breakdown:${RESET}"
    [ "$critical_count" -gt 0 ] && log_output "${RED}  ● Critical: $critical_count${RESET}"
    [ "$high_count" -gt 0 ]     && log_output "${RED}  ● High:     $high_count${RESET}"
    [ "$medium_count" -gt 0 ]   && log_output "${YELLOW}  ● Medium:   $medium_count${RESET}"
    [ "$low_count" -gt 0 ]      && log_output "${YELLOW}  ● Low:      $low_count${RESET}"

    # ---- Overall risk rating ----
    overall_label="Low"
    overall_color="$GREEN"

    if   [ "$risk_score" -ge 120 ]; then
        overall_label="Critical"
        overall_color="$RED"
    elif [ "$risk_score" -ge 80 ]; then
        overall_label="High"
        overall_color="$RED"
    elif [ "$risk_score" -ge 40 ]; then
        overall_label="Medium"
        overall_color="$YELLOW"
    fi

    log_output ""
    log_output "${BOLD}Overall risk score: $risk_score${RESET}"
    log_output "${overall_color}${BOLD}Overall rating: $overall_label${RESET}"
fi

log_output ""

# ============================================================
# NEXT STEPS
# ============================================================
log_output "${BOLD}${BLUE}╔════════════════════════════════════════════════════════════════╗${RESET}"
log_output "${BOLD}${BLUE}║                        NEXT STEPS                              ║${RESET}"
log_output "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════════╝${RESET}"
log_output ""

log_output "${YELLOW}1. Run comprehensive subdomain enumeration:${RESET}"
log_output "   subfinder -d $domain | httpx -silent | nuclei -t takeovers/"
log_output ""
log_output "${YELLOW}2. Check all subdomains with certificate transparency:${RESET}"
log_output "   Visit crt.sh: ${BLUE}https://crt.sh/?q=%.$domain${RESET}"
log_output ""
log_output "${YELLOW}3. Test each interesting host manually:${RESET}"
log_output "   curl -I https://[subdomain]"
log_output "   dig CNAME [subdomain].$domain"
log_output ""
log_output "${YELLOW}4. If this is for a bug bounty / pentest report:${RESET}"
log_output "   - Capture POC screenshots"
log_output "   - Include DNS output (dig/nslookup)"
log_output "   - Show SMTP/STARTTLS tests if relevant"
log_output "   - Explain business impact in simple terms"

log_output ""
end_time=$(date +%s)
duration=$((end_time - start_time))
log_output "${BOLD}Scan completed in ${duration}s${RESET}"
[ -n "$output_file" ] && log_output "${GREEN}Report saved: $output_file${RESET}"
log_output ""
