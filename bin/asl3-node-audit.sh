#!/usr/bin/env bash
# ASL3 Node Audit - independent read-only security and health report.
# No settings, services, firewall rules, packages or update lists are changed.
set -u
export LC_ALL=C
APP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION="$(tr -d '\r\n' < "$APP_ROOT/VERSION" 2>/dev/null || printf '0.0.0')"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || VERSION="0.0.0"
NO_COLOR=0
INTERNAL_RENDER=0
SUMMARY_FIRST=0
TIMEOUT_SECS=5
for a in "$@"; do
  case "$a" in
    --no-color) NO_COLOR=1 ;;
    --internal-render) INTERNAL_RENDER=1 ;;
    --summary-first) SUMMARY_FIRST=1 ;;
    --version) echo "ASL3 Node Audit $VERSION"; exit 0 ;;
    -h|--help) printf 'Usage: sudo bash %s [--no-color] [--summary-first]\nRead-only. No apt-get update or service changes.\n' "$0"; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$a" >&2; exit 2 ;;
  esac
done
# Render in memory first, so the priority summary is at the TOP while keeping
# every detailed section below. No disk files are created or modified.
if (( SUMMARY_FIRST == 1 && INTERNAL_RENDER == 0 )); then
  output=$(bash "$0" "${@}" --internal-render 2>&1)
  result=$?
  printf '%s\n' "$output" | awk '
    /^=== 16\. Priority findings/ {priority=1; next}
    /^=== 17\. Report limitations/ {priority=0}
    priority && /^    (WARN|FAIL|UNKNOWN)[[:space:]]/ { print "  " $0; found=1 }
    priority && /^            / { print $0 }
    END {if (!found) print "  No WARN, FAIL or UNKNOWN results."}
  ' | { printf '%s\n' '============================================================' '  PRIORITY FINDINGS — read this first' '============================================================'; cat; }
  printf '\n%s\n' '======================= FULL REPORT ========================'
  printf '%s\n' "$output"
  exit "$result"
fi
if [[ -t 1 && "$NO_COLOR" == 0 ]]; then
  GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; BLUE=$'\033[36m'; RESET=$'\033[0m'
else GREEN=; YELLOW=; RED=; BLUE=; RESET=; fi
PASS=0; WARN=0; FAIL=0; INFO=0; SKIP=0; UNKNOWN=0
declare -a FINDINGS=()
section() { printf '\n=== %s ===\n' "$1"; }
report() {
  local tag="$1" msg="$2" hint="${3:-}" color=""
  case "$tag" in
    PASS) ((PASS+=1)); color=$GREEN ;;
    WARN) ((WARN+=1)); color=$YELLOW ;;
    FAIL) ((FAIL+=1)); color=$RED ;;
    INFO) ((INFO+=1)); color=$BLUE ;;
    SKIP) ((SKIP+=1)); color=$BLUE ;;
    UNKNOWN) ((UNKNOWN+=1)); color=$YELLOW ;;
  esac
  printf '  %s[%-7s]%s %s\n' "$color" "$tag" "$RESET" "$msg"
  if [[ "$tag" == WARN || "$tag" == FAIL || "$tag" == UNKNOWN ]]; then FINDINGS+=("$tag|$msg|$hint"); fi
  if [[ -n "$hint" ]]; then
    local part
    IFS='|' read -ra parts <<< "$hint"
    for part in "${parts[@]}"; do
      part="${part# }"; part="${part% }"
      printf '            %s\n' "$part"
    done
  fi
}
have() { command -v "$1" >/dev/null 2>&1; }
root() { [[ $EUID -eq 0 ]]; }
installed() { have dpkg-query && [[ $(dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null) == ii* ]]; }
service_exists() { have systemctl && [[ $(systemctl show --property=LoadState --value "$1" 2>/dev/null) == loaded ]]; }
service_active() { systemctl is-active --quiet "$1" 2>/dev/null; }
service_enabled() { [[ $(systemctl is-enabled "$1" 2>/dev/null) == enabled ]]; }
runquick() { if have timeout; then timeout "$TIMEOUT_SECS" "$@" 2>/dev/null; else "$@" 2>/dev/null; fi; }
listen_tcp() { [[ -n "${TCPSOCKETS:-}" ]] && printf '%s\n' "$TCPSOCKETS" | awk -v p=":$1" '$4 ~ p"$" {found=1} END {exit !found}'; }
listen_udp() { [[ -n "${UDPSOCKETS:-}" ]] && printf '%s\n' "$UDPSOCKETS" | awk -v p=":$1" '$4 ~ p"$" {found=1} END {exit !found}'; }
# Returns success when an *unrestricted* local bind is seen; NOT an internet reachability test.
bind_any_tcp() { printf '%s\n' "${TCPSOCKETS:-}" | awk -v p=":$1" '$4 ~ p"$" && ($4 ~ /^0\\.0\\.0\\.0:/ || $4 ~ /^\\*:/ || $4 ~ /^\\[::\\]:/) {f=1} END{exit !f}'; }
service_status() {
  local svc="$1" desc="$2" expected="${3:-optional}" state
  if ! service_exists "$svc"; then report SKIP "$desc: not installed as a systemd service."; return; fi
  state=$(systemctl is-active "$svc" 2>/dev/null || true)
  case "$state" in
    active) report PASS "$desc: active." ;;
    failed) report FAIL "$desc: FAILED." "Inspect: systemctl status $svc --no-pager" ;;
    inactive)
      if [[ "$expected" == required ]]; then
        report WARN "$desc: inactive (required for normal node operation)." "Check: systemctl status $svc --no-pager"
      elif service_enabled "$svc"; then
        report WARN "$desc: enabled but inactive." "Check whether this service is expected to run."
      else
        report INFO "$desc: inactive/disabled (may be intentional)."
      fi ;;
    *) report UNKNOWN "$desc: state ${state:-unknown}." ;;
  esac
}

printf 'ASL3 NODE AUDIT v%s | %s\n' "$VERSION" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
printf 'Read-only local assessment. No installations, updates, service restarts or configuration changes.\n'
printf 'Sensitive addresses, passwords and configuration values are intentionally omitted.\n'
if (( SUMMARY_FIRST == 0 )); then printf 'Live report: sections print as they finish; the complete findings recap is at the end.\n'; fi
if ! root; then report WARN 'Not running as root; some checks may be incomplete.' 'Run with sudo for the fullest report.'; fi

section '1. Platform and ASL3 identification'
if [[ -r /etc/os-release ]]; then
  OS_CODENAME=$(. /etc/os-release; printf '%s' "${VERSION_CODENAME:-unknown}")
  OS_PRETTY=$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-unknown}")
  report INFO "OS: $OS_PRETTY"
else OS_CODENAME=unknown; report UNKNOWN 'Cannot identify operating system.'; fi
if ! have dpkg-query; then report FAIL 'This checker requires a Debian/dpkg-based OS.'; exit 2; fi
if installed asl3 || installed asl3-asterisk; then
  report PASS 'ASL3 package detected.'
else
  report FAIL 'ASL3 packages not detected; health results may not apply.' 'Run on an ASL3 machine; no automatic changes will be made.'
fi
case "$OS_CODENAME" in
  trixie|bookworm) report PASS "Recognized Debian release: $OS_CODENAME." ;;
  bullseye|buster|stretch) report WARN "Older Debian release ($OS_CODENAME); verify support and updates." ;;
  *) report UNKNOWN "OS codename $OS_CODENAME: support status not assessed." ;;
esac
report INFO "Running kernel: $(uname -r)"
if [[ -e /run/reboot-required || -e /var/run/reboot-required ]]; then
  report WARN 'A reboot-required marker exists.' 'To inspect marker: ls -l /run/reboot-required /var/run/reboot-required 2>/dev/null | Reboot only during planned maintenance: sudo reboot'
else
  report INFO 'No reboot-required marker (absence does NOT prove the running kernel is current).'
fi
if have dpkg-query; then
  KERNELPKGS=$(dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\n' 'linux-image-*' 'raspberrypi-kernel*' 'linux-image-rpi-*' 2>/dev/null | awk '$3 ~ /^ii/ {++n} END {print n+0}')
  report INFO "$KERNELPKGS installed kernel package(s) matched; package counts include kernel variants and do not prove boot selection."
fi
if [[ -d /boot ]]; then
  BOOTFREE=$(df -P /boot 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5);print $5}')
  if [[ "$BOOTFREE" =~ ^[0-9]+$ ]]; then
    if ((BOOTFREE >= 90)); then report FAIL '/boot filesystem is at least 90% used.'
    elif ((BOOTFREE >= 80)); then report WARN '/boot filesystem is at least 80% used.'
    else report PASS '/boot filesystem usage below 80%.'; fi
  fi
fi

section '2. Updates and package integrity'
if have apt; then
  APTLIST=$(apt list --upgradable 2>/dev/null | awk 'NR>1 && /\[upgradable from:/ {++n} END {print n+0}')
  if ((APTLIST>0)); then report WARN "$APTLIST package(s) show available updates (cached APT data)." 'To refresh: sudo apt update | To list packages: apt list --upgradable | To simulate only: sudo apt-get -s upgrade | To install when ready: sudo apt upgrade'
  else report INFO 'No upgrades shown in locally cached apt lists; they may be stale.'; fi
  LISTDATE=$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*InRelease' -printf '%T@\n' 2>/dev/null | sort -nr | head -1)
  if [[ "$LISTDATE" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    AGEDAYS=$(awk -v now="$(date +%s)" -v then="$LISTDATE" 'BEGIN{printf "%.0f", (now-then)/86400}')
    if ((AGEDAYS > 14)); then report WARN "APT metadata is approximately $AGEDAYS days old." 'To refresh the package lists: sudo apt update'
    else report INFO "APT metadata approximately $AGEDAYS days old."; fi
  else report UNKNOWN 'APT metadata freshness could not be determined.'; fi
fi
if have dpkg; then
  AUDIT=$(runquick dpkg --audit || true)
  if [[ -n "$AUDIT" ]]; then report WARN 'dpkg reports incomplete or inconsistent package states.' 'To inspect: sudo dpkg --audit'
  else report PASS 'dpkg did not report partially installed packages.'; fi
fi
if installed unattended-upgrades; then
  if have apt-config && apt-config dump 2>/dev/null | grep -q 'APT::Periodic::Unattended-Upgrade "1"'; then
    report PASS 'Unattended-upgrades periodic configuration enabled.'
  else report INFO 'Unattended-upgrades installed, but periodic configuration not confirmed enabled.'; fi
  if service_exists apt-daily-upgrade.timer; then service_status apt-daily-upgrade.timer 'Automatic upgrade timer'; fi
else report INFO 'unattended-upgrades package not installed.'; fi

section '3. Asterisk and ASL3 services'
service_status asterisk.service Asterisk required
if have asterisk; then
  AOUT=$(runquick asterisk -rx 'core show uptime' || true)
  if [[ "$AOUT" == *'System uptime:'* || "$AOUT" == *'Last reload:'* ]]; then report PASS 'Asterisk CLI responds.'
  else report WARN 'Asterisk CLI did not return expected uptime information.' 'Check: sudo asterisk -rx "core show uptime"'; fi
  REGOUT=$(runquick asterisk -rx 'rpt show registrations' || true)
  if [[ -z "$REGOUT" ]]; then report UNKNOWN 'ASL registration command returned no output.'
  elif [[ "$REGOUT" == *'No such command'* || "$REGOUT" == *'Unable to connect'* ]]; then report UNKNOWN 'Registration status command is unavailable or Asterisk is unreachable.'
  else
    report INFO 'Registration command responded; status must be interpreted against your configured nodes.'
    if printf '%s\n' "$REGOUT" | grep -Eiq 'reject|fail|unregistered|timeout'; then report WARN 'Registration output contains possible failure terminology.' 'Inspect manually: sudo asterisk -rx "rpt show registrations"'; fi
  fi
else report FAIL 'Asterisk executable not found.'; fi
if [[ -f /etc/asterisk/rpt.conf ]]; then report PASS 'rpt.conf exists.'; else report WARN 'rpt.conf not found at expected path.'; fi
if [[ -f /etc/asterisk/manager.conf ]]; then
  report INFO 'manager.conf exists; AMI access restrictions and permissions should be reviewed.'
  MODE=$(stat -c %a /etc/asterisk/manager.conf 2>/dev/null || true)
  if [[ "$MODE" =~ ^[0-9]+$ ]] && (( (8#$MODE & 8#004) != 0 )); then report WARN 'manager.conf appears world-readable.' 'Review file permissions without disrupting Asterisk.'; fi
fi
if [[ -r /var/lib/asterisk/astdb.txt ]]; then report INFO 'Local Asterisk identity database found (contents not printed).'; fi
if have ss; then
  TCPSOCKETS=$(runquick ss -H -l -t -n || true)
  UDPSOCKETS=$(runquick ss -H -l -u -n || true)
  IAX_PORT=4569
  if [[ -r /etc/asterisk/iax.conf ]]; then
    IAX_CONFIG_PORT=$(awk -F= '/^[[:space:]]*bindport[[:space:]]*=/ {v=$2; sub(/[;#].*$/, "", v); gsub(/[[:space:]]/, "", v); if (v ~ /^[0-9]+$/) port=v} END {if (port != "") print port}' /etc/asterisk/iax.conf)
    if [[ "$IAX_CONFIG_PORT" =~ ^[0-9]+$ ]] && (( IAX_CONFIG_PORT >= 1 && IAX_CONFIG_PORT <= 65535 )); then IAX_PORT="$IAX_CONFIG_PORT"; fi
  fi
  if listen_udp "$IAX_PORT"; then report PASS "IAX2 UDP/$IAX_PORT is locally listening."
  else report WARN "No UDP/$IAX_PORT listener found (verify this node needs IAX2)." 'Check: sudo ss -lunp'; fi
  if listen_tcp 5038; then
    if bind_any_tcp 5038; then report WARN 'AMI TCP/5038 bound to all interfaces; assess trusted hosts and router/firewall forwarding.'
    else report PASS 'AMI TCP/5038 is not bound to all interfaces.'; fi
  else report INFO 'No AMI TCP/5038 listener observed.'; fi
else TCPSOCKETS=; UDPSOCKETS=; report UNKNOWN 'ss not available; listener checks skipped.'; fi
if have systemctl; then
  FAILEDUNITS=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '$1 ~ /\.(service|socket|timer|mount)$/ {++n} END{print n+0}')
  if ((FAILEDUNITS>0)); then report WARN "$FAILEDUNITS failed systemd unit(s) detected." 'To inspect: systemctl --failed --no-pager'
  else report PASS 'No failed systemd units reported.'; fi
fi
for name in analog_bridge mmdvm_bridge ircddbgateway ysfgateway p25gateway nxdngateway hblink tgifd bmtd; do
  service_exists "$name.service" && service_status "$name.service" "$name"
done

section '4. Web services and dashboard discovery'
for svc in apache2 nginx php8.2-fpm php8.3-fpm php8.4-fpm php8.5-fpm cockpit.socket fail2ban; do
  service_exists "$svc" && service_status "$svc" "$svc"
done
if [[ -d /var/www/html ]]; then
  report PASS 'Web root /var/www/html exists.'
  declare -A NAMES=( [alltune2]='AllTune2' [allstar_connect]='AllStar Connect' [allstar_view]='AllStar View' [dvswitch_cockpit]='DVSwitch Cockpit' [allscan]='AllScan' [allmon2]='Allmon2' [allmon3]='Allmon3' [supermon]='Supermon' [supermon2]='Supermon2' )
  DASHCOUNT=0
  while IFS= read -r -d '' dir; do
    base=${dir##*/}
    [[ "$base" == .* ]] && continue
    [[ "$base" =~ ^(assets|css|js|images|img|vendor|node_modules|cache|uploads|data|run)$ ]] && continue
    # Report only directories that look like sites/apps; do not recurse into their code.
    if [[ -f "$dir/index.php" || -f "$dir/index.html" || -f "$dir/public/index.php" || -f "$dir/public/index.html" || -f "$dir/composer.json" || -f "$dir/VERSION" || -f "$dir/setup.sh" || -f "$dir/setup_alltune2.sh" || -f "$dir/setup_allstar_connect.sh" || -f "$dir/setup_allstar_view.sh" || -f "$dir/setup_dvswitch_cockpit.sh" || -n "${NAMES[$base]:-}" ]]; then
      ((DASHCOUNT+=1))
      if [[ "$base" =~ (\.bak$|\.old$|\.backup$|_bak$|_test$|_backup$|^backup) ]]; then
        report INFO "Backup/test web directory: $base (not assumed to be a live dashboard)."
      else
        report INFO "Web app directory: ${NAMES[$base]:-$base} (/var/www/html/$base)."
      fi
    fi
  done < <(find /var/www/html -mindepth 1 -maxdepth 1 \( -type d -o -type l \) -print0 2>/dev/null)
  ((DASHCOUNT>0)) || report INFO 'No recognized web app directory found directly under /var/www/html; virtual hosts or deeper apps may exist.'
else report INFO 'Standard web root absent; inspect virtual hosts for nonstandard application paths.'; fi
if [[ -d /etc/allmon3 ]] || installed allmon3; then
  report INFO 'Allmon3 configuration/package detected; this does not imply it should run.'
fi
# Allmon3 may be deliberately disabled to conserve memory; never treat active as inherently desirable.
if service_exists allmon3.service; then
  am_active=$(systemctl is-active allmon3.service 2>/dev/null || true)
  am_enabled=$(systemctl is-enabled allmon3.service 2>/dev/null || true)
  report INFO "Allmon3 state: active=$am_active, startup=$am_enabled; compare with operator preference."
fi
for dashboard_svc in alltune2 allstar_connect allstar_view dvswitch_cockpit allscan; do
  service_exists "$dashboard_svc.service" && service_status "$dashboard_svc.service" "Dashboard service $dashboard_svc"
done
report INFO 'Virtual-host document roots and reverse proxies may expose apps outside /var/www/html; manual review is needed.'
if have apache2ctl && service_active apache2; then
  if runquick apache2ctl -t >/dev/null 2>&1; then report PASS 'Apache configuration syntax check passed.'
  else report WARN 'Apache configuration syntax check failed or timed out.' 'Inspect: sudo apache2ctl -t'; fi
fi
if have php; then report INFO "Default PHP CLI: $(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)."
else report INFO 'PHP CLI not installed (PHP may still be present via FPM).'; fi
if have dpkg-query; then
  PHPVERS=$(dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\n' 'php*-common' 2>/dev/null | awk '$1 ~ /^php[0-9]+\.[0-9]+-common$/ && $3 ~ /^ii/ {print $1, $2}')
  if [[ -n "$PHPVERS" ]]; then
    while read -r p v; do
      report INFO "$p installed, Debian package version $v; review Debian security advisories for patch/backport status."
    done <<< "$PHPVERS"
  fi
fi
if listen_tcp 80 || listen_tcp 443; then report INFO 'HTTP and/or HTTPS port is listening locally (not proof of internet reachability).'; fi

section '5. Network, firewall and login security'
if have ip; then
  ROUTE=$(runquick ip route show default || true)
  if [[ -n "$ROUTE" ]]; then report PASS 'Default IPv4 route present.'; else report WARN 'No default IPv4 route found.'; fi
  V6GLOBAL=$(ip -6 -o addr show scope global 2>/dev/null | awk '$4 !~ /^[fF][cCdD]/ {++n} END {print n+0}')
  if ((V6GLOBAL>0)); then report INFO 'At least one global IPv6 address is configured; review IPv6 firewall and router policy.'; fi
fi
if have timedatectl; then
  SYNC=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
  case "$SYNC" in yes) report PASS 'System time reports synchronized.' ;; no) report WARN 'Time synchronization is not confirmed.' ;; *) report UNKNOWN 'Time sync status unavailable.' ;; esac
fi
if service_active fail2ban; then
  report PASS 'Fail2Ban is active.'
  if have fail2ban-client; then
    JAILS=$(runquick fail2ban-client status | sed -n 's/.*Jail list:[[:space:]]*//p' || true)
    if [[ -n "$JAILS" ]]; then report INFO 'Fail2Ban has configured jails (names omitted from summary).'; else report UNKNOWN 'Fail2Ban active but jail list not verified.'; fi
  fi
else report INFO 'Fail2Ban not active; consider exposure and whether other protections exist.'; fi
if have ufw; then
  UFWSTATE=$(runquick ufw status || true)
  if [[ "$UFWSTATE" == *'Status: active'* ]]; then
    report INFO 'ufw is active; individual allowances and default incoming policy require review.'
  fi
fi
if root && have nft; then
  NFT=$(runquick nft -a list ruleset || true)
  if [[ -n "$NFT" ]]; then
    report INFO 'nftables rules present; Fail2Ban chains alone do not prove general firewall protection.'
    if printf '%s\n' "$NFT" | grep -Eq 'hook input.*policy drop'; then report INFO 'At least one nftables input chain uses a drop policy (actual exposure depends on all rules).'; fi
  else report UNKNOWN 'No readable nftables ruleset (may be unused or inaccessible).'; fi
fi
if have sshd; then
  SSHD=$(runquick sshd -T || true)
  if [[ -n "$SSHD" ]]; then
    if grep -Eiq '^permitemptypasswords yes' <<< "$SSHD"; then report FAIL 'SSH permits empty passwords in effective configuration.'; else report PASS 'SSH does not report empty passwords enabled.'; fi
    if grep -Eiq '^permitrootlogin yes' <<< "$SSHD"; then report WARN 'SSH permits root login; check effective authentication methods.'; fi
    if grep -Eiq '^passwordauthentication yes' <<< "$SSHD"; then report INFO 'SSH password authentication enabled; consider keys and access controls.'; fi
  else report UNKNOWN 'Unable to parse effective sshd configuration.'; fi
fi
report INFO 'External reachability, router forwards, DNS mapping and upstream filtering cannot be established by local socket inspection.'

section '6. Disk, logs, memory and Raspberry Pi hardware'
for path in / /var/log; do
  VAL=$(df -P "$path" 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
  if [[ "$VAL" =~ ^[0-9]+$ ]]; then
    if ((VAL>=95)); then report FAIL "$path filesystem at $VAL% usage."
    elif ((VAL>=85)); then report WARN "$path filesystem at $VAL% usage."
    else report PASS "$path filesystem at $VAL% usage."; fi
  else report UNKNOWN "Could not read space usage for $path."; fi
done
if have free; then
  MEM=$(free -m | awk '/^Mem:/ {print $7}')
  [[ "$MEM" =~ ^[0-9]+$ ]] && report INFO "Available RAM approximately ${MEM} MiB (interpret relative to workload)."
fi
if have journalctl; then
  JUSAGE=$(runquick journalctl --disk-usage || true)
  [[ -n "$JUSAGE" ]] && report INFO 'systemd journal disk-usage data available; inspect with journalctl --disk-usage.'
fi
if have vcgencmd; then
  TEMP=$(runquick vcgencmd measure_temp || true)
  TNUM=$(sed -n "s/.*=\([0-9][0-9]*\)\..*/\1/p" <<< "$TEMP")
  if [[ "$TNUM" =~ ^[0-9]+$ ]]; then
    if ((TNUM>=80)); then report WARN "Pi temperature around ${TNUM} C."
    else report INFO "Pi temperature around ${TNUM} C."; fi
  fi
  THROTTLE=$(runquick vcgencmd get_throttled || true)
  if [[ "$THROTTLE" =~ 0x([[:xdigit:]]+) ]]; then
    VALUE=$((16#${BASH_REMATCH[1]}))
    if ((VALUE!=0)); then report WARN 'Raspberry Pi reports present or historical undervoltage/throttling flags.' 'Inspect: vcgencmd get_throttled (history flags can persist until reboot).'
    else report PASS 'No Pi throttling/undervoltage flags reported.'; fi
  else report UNKNOWN 'Pi throttle flags unavailable.'; fi
fi
if have lsusb; then
  if runquick lsusb | grep -Eiq 'CM108|CM119|C-Media'; then report INFO 'USB C-Media audio interface detected (not proof of correct Asterisk mapping).'
  else report INFO 'No recognized C-Media USB identifier detected; other audio devices may be in use.'; fi
fi

section '7. Advanced Asterisk, radio and DVSwitch diagnostics'
# No radio keying, connection changes, or credentials are accessed.
if service_active asterisk.service && have asterisk; then
  for cmd in 'core show channels count' 'iax2 show registry' 'rpt show variables'; do
    out=$(runquick asterisk -rx "$cmd" || true)
    if [[ -z "$out" || "$out" == *'No such command'* || "$out" == *'Unable to connect'* ]]; then
      report INFO "Asterisk command '$cmd' unavailable or yielded no usable result."
    else
      case "$cmd" in
        'core show channels count')
          count=$(printf '%s\n' "$out" | sed -nE 's/^([0-9]+) active channel(s)?$/\1/p' | head -1)
          if [[ "$count" =~ ^[0-9]+$ ]]; then report INFO "Asterisk active channels: $count (snapshot only)."
          else report INFO 'Asterisk channel-count command responds.'; fi ;;
        'iax2 show registry')
          if grep -Eiq 'Rejected|Unregistered|Request Sent|Timeout' <<< "$out"; then
            report WARN 'IAX2 registry output includes an unsuccessful or pending registration.' 'Inspect: sudo asterisk -rx "iax2 show registry"'
          else report INFO 'IAX2 registry command responds (review registration details privately).'; fi ;;
        *) report INFO 'App_rpt variables command responds; individual radio functions not tested.' ;;
      esac
    fi
  done
fi
if [[ -d /etc/asterisk ]]; then
  for cfg in iax.conf extensions.conf rpt.conf manager.conf; do
    if [[ -f "/etc/asterisk/$cfg" ]]; then report INFO "Asterisk configuration present: $cfg (contents not displayed)."
    else report INFO "Asterisk configuration absent: $cfg (may be generated/included or optional)."; fi
  done
  if find /etc/asterisk -maxdepth 1 -type f \( -name '*.dpkg-dist' -o -name '*.dpkg-old' -o -name '*.ucf-dist' \) -print -quit 2>/dev/null | grep -q .; then
    report WARN 'Asterisk directory has package-merge leftover files (.dpkg-dist/.dpkg-old).' 'Compare carefully against live configuration; do not overwrite automatically.'
  fi
fi
for svc in analog_bridge mmdvm_bridge ircddbgateway ysfgateway p25gateway nxdngateway; do
  if service_exists "$svc.service"; then
    en=$(systemctl is-enabled "$svc.service" 2>/dev/null || true)
    [[ "$en" == enabled ]] && ! service_active "$svc.service" && report WARN "$svc enabled at boot but not active." 'Verify whether this bridge is actually configured for use.'
  fi
done
for port in 4569 5038 8080 8443 9090; do
  if listen_tcp "$port"; then report INFO "TCP/$port listening locally (not proof of external reachability)."; fi
done

section '8. Web application and security configuration'
if service_active apache2.service; then
  if have apache2ctl; then
    if runquick apache2ctl -M | grep -q 'ssl_module'; then report INFO 'Apache SSL module loaded.'
    else report INFO 'Apache SSL module not shown in loaded modules.'; fi
    if runquick apache2ctl -M | grep -q 'rewrite_module'; then report INFO 'Apache rewrite module loaded.'; fi
    if runquick apache2ctl -M | grep -q 'headers_module'; then report INFO 'Apache headers module loaded.'; fi
    if runquick apache2ctl -M | grep -q 'remoteip_module'; then report INFO 'Apache remoteip module loaded; confirm trusted proxy list privately.'; fi
  fi
  if [[ -d /etc/apache2/sites-enabled ]]; then
    sites=$(find /etc/apache2/sites-enabled -mindepth 1 -maxdepth 1 -type l | wc -l)
    report INFO "$sites enabled Apache site configuration(s); redirects/proxies not probed."
  fi
  if [[ -d /etc/apache2/conf-enabled ]]; then
    confs=$(find /etc/apache2/conf-enabled -mindepth 1 -maxdepth 1 -type l | wc -l)
    report INFO "$confs enabled Apache shared configuration(s); includes custom security filters."
  fi
  if [[ -f /etc/apache2/mods-enabled/php8.4.load ]] || [[ -f /etc/apache2/mods-enabled/php8.2.load ]]; then
    report INFO 'Apache mod_php appears configured (not proof that every app uses it).'
  fi
fi
if have certbot; then
  report INFO 'Certbot installed; certificate expiry checks require careful parsing of locally configured certificates.'
  if [[ -d /etc/letsencrypt/live ]]; then
    certcount=0; soon=0; expired=0
    while IFS= read -r -d '' cert; do
      ((certcount+=1))
      if have openssl; then
        if ! openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1; then ((expired+=1))
        elif ! openssl x509 -in "$cert" -noout -checkend 1209600 >/dev/null 2>&1; then ((soon+=1)); fi
      fi
    done < <(find -L /etc/letsencrypt/live -maxdepth 2 -name cert.pem -type f -print0 2>/dev/null)
    if ((expired>0)); then report FAIL "$expired local Let's Encrypt certificate(s) expired." 'To inspect: sudo certbot certificates'
    elif ((soon>0)); then report WARN "$soon local Let's Encrypt certificate(s) expire within 14 days." 'To inspect certificates: sudo certbot certificates | To inspect timer: systemctl status certbot.timer --no-pager'
    elif ((certcount>0)); then report PASS "$certcount local Let's Encrypt certificate(s) valid beyond 14 days."
    else report INFO 'No readable cert.pem under the standard Let’s Encrypt live directory.'; fi
  fi
  for unit in certbot.timer snap.certbot.renew.timer; do
    if service_exists "$unit"; then
      if service_active "$unit"; then report PASS "Certificate renewal timer $unit active."
      else report WARN "Certificate renewal timer $unit inactive." 'Verify whether renewal is handled by a different mechanism.'; fi
    fi
  done
fi
printf '    %-22s %-12s %s\n' 'Dashboard' 'Version' 'Git tracked files'
for app in alltune2 allstar_connect allstar_view dvswitch_cockpit allscan; do
  d="/var/www/html/$app"
  [[ -d "$d" ]] || continue
  ver='—'; gitstate='Not checked'
  if [[ -r "$d/VERSION" ]]; then
    ver=$(head -c 48 "$d/VERSION" 2>/dev/null | tr -cd '[:alnum:]._-')
    [[ -n "$ver" ]] || ver='—'
  fi
  if [[ -d "$d/.git" ]] && have git; then
    if changes=$(runquick git -C "$d" status --porcelain --untracked-files=no); then
      if [[ -n "$changes" ]]; then gitstate='Modified'; else gitstate='Clean'; fi
    else gitstate='Unknown'; fi
  elif [[ ! -d "$d/.git" ]]; then gitstate='No Git repository'; fi
  printf '    %-22s %-12s %s\n' "${NAMES[$app]}" "$ver" "$gitstate"
done
report INFO 'Dashboard Git status checks tracked files only; app runtime is not tested.'

section '9. Firewall, Fail2Ban and protective services'
if have systemctl && service_exists firewalld.service; then
  fw_active=$(systemctl is-active firewalld.service 2>/dev/null || true)
  fw_startup=$(systemctl is-enabled firewalld.service 2>/dev/null || true)
  report INFO "Firewalld service: active=${fw_active:-unknown}, startup=${fw_startup:-unknown}."
  if [[ "$fw_active" == active ]]; then
    if have firewall-cmd; then
      fw_state=$(runquick firewall-cmd --state || true)
      fw_zone=$(runquick firewall-cmd --get-default-zone || true)
      fw_zones=$(runquick firewall-cmd --get-active-zones || true)
      [[ "$fw_state" == running ]] && report PASS 'Firewalld daemon responds to firewall-cmd.'
      [[ -n "$fw_zone" ]] && report INFO "Firewalld default zone: $fw_zone (not proof of public exposure)."
      if [[ -n "$fw_zones" ]]; then
        fw_names=$(awk 'NF==1 {printf "%s%s",sep,$1;sep=","}' <<< "$fw_zones")
        [[ -n "$fw_names" ]] && report INFO "Firewalld active zones: $fw_names (review permitted services/ports separately)."
      else report UNKNOWN 'Firewalld active zones could not be determined.'; fi
      report INFO 'To inspect Firewalld: sudo firewall-cmd --get-active-zones ; sudo firewall-cmd --list-all-zones'
    else report UNKNOWN 'Firewalld is active but firewall-cmd was not found.'; fi
  fi
fi
if service_active fail2ban.service && have fail2ban-client; then
  jails=$(runquick fail2ban-client status | sed -n 's/^.*Jail list:[[:space:]]*//p' || true)
  if [[ -n "$jails" ]]; then
    IFS=',' read -ra jailarr <<< "$jails"
    report INFO "Fail2Ban configured jail count: ${#jailarr[@]} (names withheld)."
  fi
  if have journalctl; then
    if journalctl -u fail2ban -n 100 --no-pager 2>/dev/null | grep -Eiq '(ERROR|CRITICAL|Failed to start)'; then
      report WARN 'Recent Fail2Ban journal lines contain error keywords.' 'Inspect: sudo journalctl -u fail2ban -n 100 --no-pager'
    fi
  fi
fi
if root && have nft; then
  nft_rules=$(runquick nft list ruleset || true)
  if [[ -n "$nft_rules" ]]; then
    if grep -Eq 'hook input.*policy accept' <<< "$nft_rules"; then
      report INFO 'At least one nft input chain defaults to accept; custom Fail2Ban chains alone are not a full firewall.'
    fi
    if grep -q 'addr-set-apache-' <<< "$nft_rules"; then
      report INFO 'Apache-related Fail2Ban nftables address sets detected; rule effectiveness not independently tested.'
    fi
  fi
fi
if have ss; then
  for port in 22 80 443 5038 9090; do
    if bind_any_tcp "$port"; then
      report INFO "TCP/$port bound to wildcard address: assess firewall, router forwards, and IPv6 separately."
    fi
  done
fi

section '10. Resource pressure, storage wear and boot health'
if [[ -r /proc/pressure/cpu ]]; then
  cpu_psi=$(sed -n 's/^some .*avg10=\([0-9.]*\).*/\1/p' /proc/pressure/cpu | head -1)
  [[ -n "$cpu_psi" ]] && report INFO "CPU pressure avg10: ${cpu_psi}% (snapshot)."
fi
if [[ -r /proc/pressure/memory ]]; then
  mem_psi=$(sed -n 's/^some .*avg10=\([0-9.]*\).*/\1/p' /proc/pressure/memory | head -1)
  [[ -n "$mem_psi" ]] && report INFO "Memory pressure avg10: ${mem_psi}% (snapshot)."
fi
if [[ -r /proc/pressure/io ]]; then
  io_psi=$(sed -n 's/^some .*avg10=\([0-9.]*\).*/\1/p' /proc/pressure/io | head -1)
  [[ -n "$io_psi" ]] && report INFO "I/O pressure avg10: ${io_psi}% (snapshot)."
fi
if [[ -r /proc/loadavg ]]; then
  read -r load1 load5 load15 _ < /proc/loadavg
  report INFO "System load averages (1/5/15 min): $load1 / $load5 / $load15."
fi
if [[ -r /proc/uptime ]]; then
  read -r uptime_seconds _ < /proc/uptime
  uptime_days=${uptime_seconds%%.*}
  report INFO "System uptime: $((uptime_days/86400))d $(((uptime_days%86400)/3600))h $(((uptime_days%3600)/60))m."
fi
if have free; then
  memory_line=$(free -m | awk '/^Mem:/ {printf "%d/%d",$3,$2}')
  [[ -n "$memory_line" ]] && report INFO "RAM used/total: ${memory_line} MiB (includes cache; see available RAM in hardware section)."
fi
if have df; then
  inode_pct=$(df -Pi / | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
  if [[ "$inode_pct" =~ ^[0-9]+$ ]]; then
    if ((inode_pct>=95)); then report FAIL "Root filesystem inode use at ${inode_pct}%."
    elif ((inode_pct>=85)); then report WARN "Root filesystem inode use at ${inode_pct}%."
    else report PASS "Root filesystem inode use at ${inode_pct}%."; fi
  fi
fi
if [[ -d /var/log ]]; then
  large_count=$(find /var/log -xdev -type f -size +100M 2>/dev/null | wc -l)
  if ((large_count>0)); then report WARN "$large_count log file(s) larger than 100 MiB in /var/log." 'Inspect sizes; do not delete logs without knowing rotation and retention requirements.'
  else report PASS 'No log files above 100 MiB in the /var/log tree.'; fi
fi
if [[ -e /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq ]]; then
  report INFO 'CPU frequency scaling interface present (low frequency can be normal when idle).'
fi
if [[ -d /sys/class/thermal ]]; then report INFO 'Thermal sensors available; Pi temperature/throttle indicators reported above when supported.'; fi
if have systemctl; then
  if systemctl is-system-running --quiet 2>/dev/null; then report PASS 'systemd reports system running normally.'
  else report INFO 'systemd overall state not "running"; may be degraded, starting or maintenance state.'; fi
fi

section '11. Package-upgrade impact indicators'
if have dpkg-query; then
  for pkg in asl3 asl3-asterisk allmon3 apache2 php8.4-common fail2ban; do
    if installed "$pkg"; then
      v=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)
      report INFO "Installed $pkg: $v."
    fi
  done
fi
report INFO 'Disabled services can be re-enabled by future package operations; this audit shows current state but cannot infer operator preferences without a saved baseline.'
report INFO 'A future explicit opt-in snapshot/diff mode can detect service and config changes across upgrades without changing the monitored services.'

section '12. Running services and startup inventory'
if have systemctl; then
  # Names and systemd state only: no command lines, arguments, or environment variables.
  active_units=$(runquick systemctl list-units --type=service --state=running --no-legend --plain --no-pager || true)
  active_count=$(printf '%s\n' "$active_units" | awk '$1 ~ /\.service$/ {n++} END {print n+0}')
  report INFO "$active_count currently running system services (snapshot)."
  if ((active_count>0)); then
    printf '    Running system services (unit names only):\n'
    printf '%s\n' "$active_units" | awk '$1 ~ /\.service$/ {print $1}' | sort -f | while IFS= read -r unit; do
      printf '      %-42s\n' "$unit"
    done
  fi
  enabled_units=$(runquick systemctl list-unit-files --type=service --state=enabled --no-legend --plain --no-pager || true)
  enabled_count=$(printf '%s\n' "$enabled_units" | awk '$1 ~ /\.service$/ {n++} END {print n+0}')
  report INFO "$enabled_count enabled system service unit files (enabled does not necessarily mean running)."
  if ((enabled_count>0)); then
    printf '    Enabled services not currently running (inspect whether intentional):\n'
    inactive_enabled=0
    while IFS= read -r svc; do
      [[ -n "$svc" ]] || continue
      if ! service_active "$svc"; then
        printf '      %s\n' "$svc"
        ((inactive_enabled+=1))
      fi
    done < <(printf '%s\n' "$enabled_units" | awk '$1 ~ /\.service$/ {print $1}' | sort -f)
    ((inactive_enabled>0)) || printf '      None found.\n'
  fi
  failed_units=$(runquick systemctl list-units --type=service --state=failed --no-legend --plain --no-pager || true)
  failed_count=$(printf '%s\n' "$failed_units" | awk '$1 ~ /\.service$/ {n++} END {print n+0}')
  if ((failed_count>0)); then
    report FAIL "$failed_count failed system service(s)." 'To inspect: systemctl --failed --type=service --no-pager'
    printf '%s\n' "$failed_units" | awk '$1 ~ /\.service$/ {print "      " $1}'
  else
    report PASS 'No failed system services in systemd inventory.'
  fi
else
  report UNKNOWN 'systemctl unavailable; cannot enumerate services.'
fi
if have loginctl; then
  user_mgrs=$(runquick loginctl list-users --no-legend 2>/dev/null | awk 'NF>=2 {n++} END {print n+0}' || true)
  report INFO "Active login users with user-manager potential: ${user_mgrs:-unknown}; user-level services require per-user inspection."
fi

section '13. Scheduled work: cron, anacron and systemd timers'
if have systemctl; then
  active_timers=$(runquick systemctl list-timers --all --no-legend --plain --no-pager || true)
  timer_units=$(runquick systemctl list-unit-files --type=timer --no-legend --plain --no-pager || true)
  timer_count=$(printf '%s\n' "$timer_units" | awk '$1 ~ /\.timer$/ {n++} END {print n+0}')
  report INFO "$timer_count installed systemd timer units (enabled and disabled)."
  if ((timer_count>0)); then
    printf '    Timer unit                                Startup      Active\n'
    while read -r unit startup rest; do
      [[ "$unit" == *.timer ]] || continue
      active=$(systemctl is-active "$unit" 2>/dev/null || true)
      printf '      %-41s %-12s %s\n' "$unit" "$startup" "$active"
    done <<< "$timer_units"
  fi
  failed_timer_count=$(runquick systemctl list-units --type=timer --state=failed --no-legend --plain --no-pager | awk '$1 ~ /\.timer$/ {n++} END {print n+0}' || true)
  if [[ "${failed_timer_count:-0}" =~ ^[0-9]+$ ]] && ((failed_timer_count>0)); then
    report WARN "$failed_timer_count systemd timer unit(s) in failed state." 'To inspect: systemctl --failed --type=timer --no-pager'
  fi
else
  report UNKNOWN 'Cannot inventory systemd timers without systemctl.'
fi
if service_exists cron.service; then
  service_status cron.service 'Cron scheduler' optional
elif service_exists crond.service; then
  service_status crond.service 'Cron scheduler' optional
else
  report INFO 'Cron service not detected; systemd timers may be used instead.'
fi
if installed anacron; then
  service_status anacron.service 'Anacron catch-up scheduler' optional
else
  report INFO 'Anacron package not installed.'
fi
# Never print raw crontab lines: scheduled command arguments may hold secrets.
if [[ -r /etc/crontab ]]; then
  n=$(awk '/^[[:space:]]*($|#)/ {next} {n++} END{print n+0}' /etc/crontab)
  report INFO "/etc/crontab: $n active-looking schedule lines (syntax and execution not verified)."
fi
if [[ -d /etc/cron.d ]]; then
  printf '    /etc/cron.d entries (file names only):\n'
  cron_files=0
  while IFS= read -r -d '' path; do
    [[ -f "$path" && ! -L "$path" ]] || continue
    b=${path##*/}
    [[ "$b" == .* || "$b" == *~ || "$b" == *.bak || "$b" == *.dpkg-* ]] && continue
    n=$(awk '/^[[:space:]]*($|#)/ {next} {n++} END{print n+0}' "$path" 2>/dev/null || echo '?')
    printf '      %-40s %s schedule lines\n' "$b" "$n"
    ((cron_files+=1))
  done < <(find /etc/cron.d -mindepth 1 -maxdepth 1 -type f -print0 2>/dev/null | sort -z)
  report INFO "$cron_files ordinary schedule files found in /etc/cron.d."
fi
for interval in hourly daily weekly monthly yearly; do
  d="/etc/cron.$interval"
  if [[ -d "$d" ]]; then
    names=()
    while IFS= read -r -d '' path; do
      b=${path##*/}
      [[ "$b" == .* || "$b" == *~ || "$b" == *.bak || "$b" == *.dpkg-* ]] && continue
      names+=("$b")
    done < <(find "$d" -mindepth 1 -maxdepth 1 -type f -print0 2>/dev/null | sort -z)
    report INFO "$d: ${#names[@]} candidate task(s)."
    if ((${#names[@]}>0)); then printf '      %s\n' "${names[@]}"; fi
  fi
done
if root; then
  if have crontab; then
    # Include root and every local user with a spool crontab, not every passwd user.
    declare -A cron_users=([root]=1)
    for spool in /var/spool/cron/crontabs /var/spool/cron; do
      [[ -d "$spool" ]] || continue
      while IFS= read -r -d '' path; do
        u=${path##*/}
        [[ "$u" =~ ^[a-zA-Z0-9_.-]+$ ]] && cron_users["$u"]=1
      done < <(find "$spool" -mindepth 1 -maxdepth 1 -type f -print0 2>/dev/null)
    done
    cron_user_count=0; cron_job_count=0
    printf '    Per-user cron (usernames and commands suppressed for shareable report):\n'
    while IFS= read -r u; do
      raw=$(runquick crontab -u "$u" -l 2>/dev/null || true)
      [[ -n "$raw" ]] || continue
      n=$(printf '%s\n' "$raw" | awk '/^[[:space:]]*($|#)/ {next} {n++} END{print n+0}')
      if ((n>0)); then
        ((cron_user_count+=1)); ((cron_job_count+=n))
        printf '      Account #%d: %d scheduled line(s)\n' "$cron_user_count" "$n"
      fi
    done < <(printf '%s\n' "${!cron_users[@]}" | sort)
    report INFO "$cron_job_count scheduled crontab line(s) across $cron_user_count local account(s), including root when present."
  else
    report UNKNOWN 'crontab command unavailable; per-user cron jobs not inspected.'
  fi
else
  report SKIP 'Per-user crontabs require root for comprehensive enumeration.'
fi
report INFO 'Cron inventory verifies file presence and candidate lines, not that scheduled jobs run successfully; user-level systemd timers and external schedulers require separate inspection.'


section '14. Kernel, firmware and boot diagnostics'
RUNNING_KERNEL=$(uname -r)
report INFO "Running kernel: $RUNNING_KERNEL"
if [[ "$RUNNING_KERNEL" == *2712* ]]; then flavor=2712
elif [[ "$RUNNING_KERNEL" == *v8* ]]; then flavor=v8
else flavor=unknown; fi
report INFO "Kernel flavor: $flavor (comparisons only within this flavor)."
if [[ -d "/lib/modules/$RUNNING_KERNEL" ]]; then
  report PASS "Matching module directory exists: /lib/modules/$RUNNING_KERNEL."
else
  report WARN 'Running kernel has no matching module directory.' 'Check: uname -r | Check: ls -ld /lib/modules/$(uname -r)'
fi
if have dpkg-query; then
  for pkg in linux-image-rpi-2712 linux-image-rpi-v8 linux-base-rpi-2712 linux-base-rpi-v8 raspi-firmware rpi-eeprom; do
    if installed "$pkg"; then
      v=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)
      report INFO "Installed $pkg: $v"
    fi
  done
fi
if [[ -d /lib/modules ]]; then
  printf '    Installed kernel module trees (version/flavor):\n'
  find /lib/modules -mindepth 1 -maxdepth 1 -type d -printf '      %f\n' 2>/dev/null | sort -V
  report INFO 'Multiple kernel trees are normal on Pi models with multiple flavors; no cross-flavor comparison is performed.'
fi
if [[ -d /boot/firmware ]]; then bootdir=/boot/firmware; else bootdir=/boot; fi
boot_space=$(df -hP "$bootdir" 2>/dev/null | awk 'NR==2 {print $4 " free; " $5 " used"}')
[[ -n "$boot_space" ]] && report INFO "Boot filesystem ($bootdir): $boot_space."
for config in "$bootdir/config.txt" "$bootdir/cmdline.txt"; do
  [[ -r "$config" ]] && report INFO "Boot configuration file present: $config (contents hidden)."
done
if have vcgencmd; then
  bootloader=$(runquick vcgencmd bootloader_version | head -n 1 || true)
  [[ -n "$bootloader" ]] && report INFO "Pi bootloader version information available: $bootloader."
fi
if have journalctl; then
  # Preserve unknown failures, instead of turning an unreadable journal into zero errors.
  if kernel_log=$(runquick journalctl -k -b -p err --no-pager -q); then
    # This exact Raspberry Pi firmware request has been observed as noncritical;
    # do not classify other firmware failures as benign.
    known_pi=$(printf '%s\n' "$kernel_log" | grep -Ec 'raspberrypi-firmware .*Request 0x00030097 returned status 0x80000001' || true)
    other_errors=$(printf '%s\n' "$kernel_log" | grep -cvE '^$|raspberrypi-firmware .*Request 0x00030097 returned status 0x80000001' || true)
    if (( known_pi > 0 )); then
      report INFO "$known_pi Raspberry Pi firmware EEPROM-status request message(s) seen (0x00030097 / 0x80000001); generally noncritical in isolation."
    fi
    if (( other_errors > 0 )); then
      report WARN "$other_errors other kernel error-priority message(s) this boot." 'Inspect locally: sudo journalctl -k -b -p err --no-pager'
    else
      report PASS 'No other error-priority kernel messages this boot.'
    fi
  else
    report UNKNOWN 'Could not read kernel error logs (journal unavailable, access denied, or timed out).' 'Inspect locally: sudo journalctl -k -b -p err --no-pager'
  fi
fi
report INFO 'A newer kernel available in APT cannot be established from installed package versions alone; inspect: apt policy linux-image-rpi-2712 linux-image-rpi-v8'

section '15. Suspicious mining activity and persistence indicators'
report INFO 'This is a heuristic screen, NOT malware detection or proof of a clean system.'
if have ps; then
  printf '    Highest CPU processes (snapshot; executable name only):\n'
  ps -eo pid=,comm=,pcpu=,pmem= --sort=-pcpu 2>/dev/null | head -n 8 | awk '{printf "      PID %-8s %-27s CPU %6s%% MEM %6s%%\n",$1,$2,$3,$4}'
  suspect=$(ps -eo pid=,comm= 2>/dev/null | awk 'BEGIN{IGNORECASE=1} {n=tolower($2); if (n ~ /^(xmrig|xmr-stak|cpuminer|minerd|ccminer|ethminer|nbminer|t-rex|lolminer|kinsing)$/) print $1 ":" $2}' | paste -sd ', ' -)
  if [[ -n "$suspect" ]]; then
    report WARN "Process names match known mining tools: $suspect (verify legitimacy)." 'Inspect: sudo ps -eo pid,user,comm,pcpu,pmem --sort=-pcpu | head -n 25'
  else
    report INFO 'No obvious mining-tool process names among visible processes; hidden or renamed miners are not ruled out.'
  fi
  high=$(ps -eo pid=,comm=,pcpu= --sort=-pcpu 2>/dev/null | awk '$3+0 >= 85 {print $1":"$2"("$3"%)"}' | head -n 5 | paste -sd ', ' -)
  if [[ -n "$high" ]]; then report WARN "Very high CPU processes observed: $high (can be legitimate)." 'Inspect: ps -eo pid,comm,pcpu,pmem --sort=-pcpu | head -n 20'; fi
else report UNKNOWN 'ps unavailable; cannot examine running processes.'; fi
if have ss; then
  # Port numbers are weak indicators. No remote addresses or URLs are included.
  mining_ports=$(runquick ss -Hnt state established 2>/dev/null | awk '{print $5}' | sed -nE 's/.*:([0-9]+)$/\1/p' | grep -E '^(3333|4444|5555|7777|14444|14433)$' | sort -u | paste -sd ',' - || true)
  if [[ -n "$mining_ports" ]]; then
    report WARN "Established outbound TCP connections use commonly seen mining-pool ports: $mining_ports (not conclusive)." 'Inspect locally: sudo ss -ntp state established'
  else
    report INFO 'No established connections on sampled common mining-pool TCP ports; other ports/protocols remain possible.'
  fi
fi
if [[ -d /etc/systemd/system ]]; then
  suspect_units=$(find /etc/systemd/system -maxdepth 3 \( -type f -o -type l \) -name '*.service' -printf '%f\n' 2>/dev/null | grep -Ei '(^|[-_.])(xmrig|miner|kinsing|cryptominer)([-_.]|$)' | sort -u | paste -sd ',' - || true)
  if [[ -n "$suspect_units" ]]; then report WARN "Suspiciously named systemd unit(s): $suspect_units." 'Inspect: systemctl cat UNITNAME (replace UNITNAME with the unit above)'
  else report INFO 'No explicitly miner-named unit files in /etc/systemd/system; disguised services are not ruled out.'; fi
fi
report INFO 'Cron jobs and timers are inventoried in section 13; automatic analysis of their commands is intentionally limited to avoid exposing credentials.'
report INFO 'A security scan cannot confirm a system is uncompromised. Unexpected load, users, files, network connections and persistence merit targeted investigation.'

section '16. Priority findings and limitations' 
if ((${#FINDINGS[@]})); then
  printf '  Actionable findings first (no automatic fixes):\n'
  for entry in "${FINDINGS[@]}"; do
    IFS='|' read -r severity message hint <<< "$entry"
    printf '    %-7s %s\n' "$severity" "$message"
    if [[ -n "$hint" ]]; then
      IFS='|' read -ra parts <<< "$hint"
      for part in "${parts[@]}"; do
        part="${part# }"; part="${part% }"
        printf '            %s\n' "$part"
      done
    fi
  done
else
  printf '  No warnings, failures or unknown results in the checks executed.\n'
fi

section '17. Report limitations and summary'
report INFO 'This tool does not modify the node, test live radio audio, externally probe ports, or verify every application-specific config.'
report INFO 'Review all WARN/FAIL items before taking action; service/port absence may be intentional.'
printf '\nTOTAL: %d PASS | %d WARN | %d FAIL | %d INFO | %d SKIP | %d UNKNOWN\n' "$PASS" "$WARN" "$FAIL" "$INFO" "$SKIP" "$UNKNOWN"
if ((FAIL>0)); then exit 1; elif ((WARN>0 || UNKNOWN>0)); then exit 3; else exit 0; fi
