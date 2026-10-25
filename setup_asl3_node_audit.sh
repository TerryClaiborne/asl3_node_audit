#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/var/www/html/asl3_node_audit"
WEB_USER="www-data"
WEB_GROUP="www-data"
CONFIG_FILE="$APP_DIR/config.ini"
CONFIG_EXAMPLE="$APP_DIR/config.ini.example"
APACHE_CONF_NAME="asl3-node-audit"
APACHE_POLLING_NAME="asl3-node-audit-polling"
APACHE_CONF="/etc/apache2/conf-available/${APACHE_CONF_NAME}.conf"
APACHE_POLLING_CONF="/etc/apache2/conf-available/${APACHE_POLLING_NAME}.conf"
SERVICE_FILE="/etc/systemd/system/asl3-node-audit.service"
TIMER_FILE="/etc/systemd/system/asl3-node-audit.timer"
BACKUP_ROOT="/var/backups/asl3-node-audit"
LOCK_FILE="/run/lock/asl3-node-audit-setup.lock"
ACTION="install"
ROLLBACK_DIR=""

# Exact legacy files retired by the production layout. They are backed up before removal.
OBSOLETE_RELATIVE=(
  public/auth.php public/setup.php bin/manage_login.php
  index.php live.php app.js style.css .htaccess
  docs/apache-node-audit.conf docs/apache-node-audit-polling.conf docs/RELEASE-GATES.md
)

case "${1:-}" in
  "") ;;
  --set-admin-password) ACTION="set-password" ;;
  --enable-auth) ACTION="enable-auth" ;;
  --disable-auth) ACTION="disable-auth" ;;
  --uninstall) ACTION="uninstall" ;;
  --rollback)
    ACTION="rollback"
    ROLLBACK_DIR="${2:-}"
    ;;
  --help|-h)
    cat <<USAGE
Usage:
  sudo $APP_DIR/setup_asl3_node_audit.sh
  sudo $APP_DIR/setup_asl3_node_audit.sh --set-admin-password
  sudo $APP_DIR/setup_asl3_node_audit.sh --enable-auth
  sudo $APP_DIR/setup_asl3_node_audit.sh --disable-auth
  sudo $APP_DIR/setup_asl3_node_audit.sh --uninstall
  sudo $APP_DIR/setup_asl3_node_audit.sh --rollback /var/backups/asl3-node-audit/setup-YYYYMMDDTHHMMSSZ-XXXXXX

Normal setup installs or updates ASL3 Node Audit, preserves local config and
password hashes, installs only this application's Apache/systemd files, and
starts the scheduled monitor. No sudoers entry is installed.
USAGE
    exit 0
    ;;
  *) echo "Unknown option: ${1:-}" >&2; exit 2 ;;
esac

fail() { echo "[ERROR] $*" >&2; exit 1; }
warn() { echo "[WARN] $*" >&2; }
ok() { echo "[OK] $*"; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "Run this installer with sudo or as root."
mkdir -p /run/lock
[[ ! -L "$LOCK_FILE" ]] || fail "Unsafe setup lock symlink: $LOCK_FILE"
exec 9>"$LOCK_FILE"
flock -n 9 || fail "Another ASL3 Node Audit setup is already running."

get_key() {
  local key="$1" file="$2"
  awk -v k="$key" '
    $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {
      v=$0
      sub(/^[^=]*=/, "", v)
      sub(/^[[:space:]]+/, "", v)
      sub(/[[:space:]]+$/, "", v)
      if (v ~ /^".*"$/) { sub(/^"/, "", v); sub(/"$/, "", v) }
      print v
      exit
    }
  ' "$file" 2>/dev/null || true
}

valid_password_hash() {
  local hash="$1"
  [[ -n "$hash" ]] || return 1
  printf '%s' "$hash" | php -r '$h=stream_get_contents(STDIN); $i=password_get_info($h); exit(!empty($i["algo"]) ? 0 : 1);'
}

set_key() {
  local key="$1" value="$2" file="$3" tmp
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$value" '
    BEGIN { done=0 }
    $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {
      if (!done) { print k "=" v; done=1 }
      next
    }
    { print }
    END { if (!done) print k "=" v }
  ' "$file" > "$tmp"
  install -o root -g "$WEB_GROUP" -m 0640 "$tmp" "$file"
  rm -f "$tmp"
}

remove_obsolete_https_host() {
  local file="$1" tmp
  tmp="$(mktemp)"
  awk '!/^[[:space:]]*#?[[:space:]]*HTTPS_HOST[[:space:]]*=/' "$file" > "$tmp"
  install -o root -g "$WEB_GROUP" -m 0640 "$tmp" "$file"
  rm -f "$tmp"
}

find_rpt_files() {
  local root="/etc/asterisk/rpt.conf"
  [[ -r "$root" ]] || return 0
  printf '%s\n' "$root"
  awk '
    /^[[:space:]]*#include[[:space:]]+/ {
      p=$2
      gsub(/["<>]/, "", p)
      if (p ~ /^\//) print p; else print "/etc/asterisk/" p
    }
  ' "$root" 2>/dev/null
}

detect_node() {
  local candidates="" file section
  if [[ -r /etc/asterisk/savenode.conf ]]; then
    candidates="$(sed -nE 's/^[[:space:]]*NODE[[:space:]]*=[[:space:]]*"?([0-9]{4,7})"?[[:space:]]*([#;].*)?$/\1/p' /etc/asterisk/savenode.conf | sort -u)"
    if [[ $(printf '%s\n' "$candidates" | sed '/^$/d' | wc -l) -eq 1 ]]; then
      printf '%s' "$candidates"
      return 0
    fi
  fi
  candidates=""
  while IFS= read -r file; do
    [[ -r "$file" ]] || continue
    while IFS= read -r section; do candidates+="$section"$'\n'; done < <(
      sed -nE 's/^[[:space:]]*\[([0-9]{4,7})\][[:space:]]*(\([^)]*\))?[[:space:]]*(;.*)?$/\1/p' "$file"
    )
  done < <(find_rpt_files)
  candidates="$(printf '%s' "$candidates" | sed '/^$/d' | sort -u)"
  if [[ $(printf '%s\n' "$candidates" | sed '/^$/d' | wc -l) -eq 1 ]]; then
    printf '%s' "$candidates"
  fi
}

detect_local_ipv4() {
  local addr=""
  if command -v ip >/dev/null 2>&1; then
    addr="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '
      { for (i=1; i<=NF; i++) if ($i == "src" && (i+1) <= NF) { print $(i+1); exit } }
    ' || true)"
  fi
  if [[ ! "$addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$addr" == 127.* ]]; then
    addr="$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $0 !~ /^127\./ { print; exit }' || true)"
  fi
  if [[ "$addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$addr" != 127.* ]]; then
    printf '%s' "$addr"
  fi
}

show_access_info() {
  local addr
  addr="$(detect_local_ipv4 || true)"
  echo
  if [[ -n "$addr" ]]; then
    echo "Dashboard: http://$addr/asl3_node_audit/"
  else
    echo "Dashboard: http://YOUR-NODE-IP-ADDRESS/asl3_node_audit/"
  fi
}

show_auth_status() {
  local enabled user saved_hash
  [[ -f "$CONFIG_FILE" ]] || return 0
  enabled="$(get_key ASL3_NODE_AUDIT_AUTH_ENABLED "$CONFIG_FILE")"
  user="$(get_key ASL3_NODE_AUDIT_ADMIN_USER "$CONFIG_FILE")"
  saved_hash="$(get_key ASL3_NODE_AUDIT_ADMIN_PASSWORD_HASH "$CONFIG_FILE")"
  [[ -n "$user" ]] || user="admin"
  if [[ "$enabled" == "1" && -n "$saved_hash" ]]; then
    echo "Application login: ENABLED (user: $user; signed-out dashboard remains view-only)"
    echo "To log in: open the dashboard, click Login, and enter the admin password."
    echo "The login page asks for the password only."
    echo "Change the administrator password:"
    echo "sudo $APP_DIR/setup_asl3_node_audit.sh --set-admin-password"
    echo "Disable login while preserving the saved password hash:"
    echo "sudo $APP_DIR/setup_asl3_node_audit.sh --disable-auth"
  elif [[ "$enabled" == "1" ]]; then
    echo "[WARN] Application login is enabled, but no password hash is configured."
    echo "Set the administrator password:"
    echo "sudo $APP_DIR/setup_asl3_node_audit.sh --set-admin-password"
  else
    echo "Application login: DISABLED. Dashboard is fully interactive and no Login button is shown."
    echo "Set an administrator password and enable Login:"
    echo "sudo $APP_DIR/setup_asl3_node_audit.sh --set-admin-password"
    if [[ -n "$saved_hash" ]]; then
      echo "Re-enable Login using the saved password hash:"
      echo "sudo $APP_DIR/setup_asl3_node_audit.sh --enable-auth"
    fi
  fi
}

set_password() {
  command -v php >/dev/null 2>&1 || fail "php is required."
  [[ -f "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] || fail "Missing or unsafe config.ini. Run normal setup first."
  [[ -r /dev/tty && -w /dev/tty ]] || fail "An interactive terminal is required."
  local p1="" p2="" hash=""
  IFS= read -r -s -p "New ASL3 Node Audit admin password: " p1 < /dev/tty || fail "Unable to read password."
  printf '\n' > /dev/tty
  [[ -n "$p1" ]] || fail "Password cannot be empty."
  IFS= read -r -s -p "Confirm password: " p2 < /dev/tty || { printf '\n' > /dev/tty; fail "Unable to read confirmation."; }
  printf '\n' > /dev/tty
  [[ "$p1" == "$p2" ]] || { unset p1 p2; fail "Passwords did not match."; }
  hash="$(printf '%s' "$p1" | php -r '$p=stream_get_contents(STDIN); $h=password_hash($p, PASSWORD_DEFAULT); if(!is_string($h)) exit(1); echo $h;')" || fail "Password hashing failed."
  unset p1 p2
  [[ -n "$hash" ]] || fail "Password hashing failed."
  set_key ASL3_NODE_AUDIT_ADMIN_USER '"admin"' "$CONFIG_FILE"
  set_key ASL3_NODE_AUDIT_ADMIN_PASSWORD_HASH "\"$hash\"" "$CONFIG_FILE"
  set_key ASL3_NODE_AUDIT_AUTH_ENABLED "1" "$CONFIG_FILE"
  unset hash
  ok "ASL3 Node Audit application login is enabled; signed-out dashboard remains view-only."
  show_access_info
  show_auth_status
}

if [[ "$ACTION" == "set-password" ]]; then set_password; exit 0; fi
if [[ "$ACTION" == "enable-auth" ]]; then
  [[ -f "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] || fail "Missing or unsafe config.ini. Run normal setup first."
  saved_hash="$(get_key ASL3_NODE_AUDIT_ADMIN_PASSWORD_HASH "$CONFIG_FILE")"
  [[ -n "$saved_hash" ]] || fail "No saved password hash exists. Run --set-admin-password first."
  valid_password_hash "$saved_hash" || fail "Saved password hash is invalid. Run --set-admin-password."
  unset saved_hash
  set_key ASL3_NODE_AUDIT_ADMIN_USER '"admin"' "$CONFIG_FILE"
  set_key ASL3_NODE_AUDIT_AUTH_ENABLED "1" "$CONFIG_FILE"
  ok "Application login enabled using the saved password hash; signed-out dashboard remains view-only."
  show_access_info
  show_auth_status
  exit 0
fi
if [[ "$ACTION" == "disable-auth" ]]; then
  [[ -f "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] || fail "Missing or unsafe config.ini. Run normal setup first."
  set_key ASL3_NODE_AUDIT_AUTH_ENABLED "0" "$CONFIG_FILE"
  ok "Application login disabled; the saved password hash was preserved."
  show_access_info
  show_auth_status
  exit 0
fi

restore_backup() {
  local dir="$1"
  [[ -d "$dir" && ! -L "$dir" ]] || fail "Invalid rollback directory: $dir"
  [[ -f "$dir/backup.marker" ]] || fail "Not an ASL3 Node Audit installer backup: $dir"

  # An uninstall backup contains the complete application and can be fully restored.
  if [[ -f "$dir/application-before-uninstall.tar.gz" ]]; then
    [[ ! -e "$APP_DIR" ]] || fail "Rollback target already exists: $APP_DIR"
    tar -C /var/www/html -xzf "$dir/application-before-uninstall.tar.gz"
  fi

  if [[ -f "$dir/config.ini" ]]; then
    install -d -o root -g root -m 0755 "$APP_DIR"
    install -o root -g "$WEB_GROUP" -m 0640 "$dir/config.ini" "$CONFIG_FILE"
  elif [[ -f "$dir/no-config" ]]; then
    rm -f "$CONFIG_FILE"
  fi

  # Restore exact legacy files only when they were present before this setup.
  if [[ -d "$dir/obsolete" ]]; then
    install -d -o root -g root -m 0755 "$APP_DIR"
    cp -a "$dir/obsolete/." "$APP_DIR/"
  fi

  for pair in \
    "$APACHE_CONF:apache.conf:no-apache-conf" \
    "$APACHE_POLLING_CONF:apache-polling.conf:no-apache-polling" \
    "$SERVICE_FILE:service:no-service" \
    "$TIMER_FILE:timer:no-timer"; do
    IFS=: read -r target saved absent <<< "$pair"
    if [[ -f "$dir/$saved" ]]; then install -o root -g root -m 0644 "$dir/$saved" "$target";
    elif [[ -f "$dir/$absent" ]]; then rm -f "$target"; fi
  done

  if command -v a2enconf >/dev/null 2>&1; then
    if [[ -f "$dir/apache-enabled" ]]; then a2enconf "$APACHE_CONF_NAME" >/dev/null 2>&1 || true; else a2disconf "$APACHE_CONF_NAME" >/dev/null 2>&1 || true; fi
    if [[ -f "$dir/apache-polling-enabled" ]]; then a2enconf "$APACHE_POLLING_NAME" >/dev/null 2>&1 || true; else a2disconf "$APACHE_POLLING_NAME" >/dev/null 2>&1 || true; fi
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [[ -f "$dir/timer-enabled" ]]; then systemctl enable --now asl3-node-audit.timer >/dev/null 2>&1 || true; else systemctl disable --now asl3-node-audit.timer >/dev/null 2>&1 || true; fi
  if apache2ctl configtest >/dev/null 2>&1; then systemctl reload apache2.service >/dev/null 2>&1 || true; fi
  ok "Installer-managed configuration restored from $dir"
}

if [[ "$ACTION" == "rollback" ]]; then
  [[ -n "$ROLLBACK_DIR" ]] || fail "--rollback requires a backup directory."
  restore_backup "$ROLLBACK_DIR"
  exit 0
fi

make_backup() {
  local stamp dir
  [[ ! -L "$BACKUP_ROOT" ]] || fail "Unsafe backup-root symlink: $BACKUP_ROOT"
  [[ ! -L "$CONFIG_FILE" ]] || fail "Unsafe config.ini symlink: $CONFIG_FILE"
  for managed in "$APACHE_CONF" "$APACHE_POLLING_CONF" "$SERVICE_FILE" "$TIMER_FILE"; do
    [[ ! -L "$managed" ]] || fail "Unsafe managed-file symlink: $managed"
  done
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  install -d -o root -g root -m 0700 "$BACKUP_ROOT"
  dir="$(mktemp -d "$BACKUP_ROOT/setup-${stamp}-XXXXXX")"
  chown root:root "$dir"
  chmod 0700 "$dir"
  : > "$dir/backup.marker"
  if [[ -f "$CONFIG_FILE" ]]; then cp -a "$CONFIG_FILE" "$dir/config.ini"; else : > "$dir/no-config"; fi
  if [[ -f "$APACHE_CONF" ]]; then cp -a "$APACHE_CONF" "$dir/apache.conf"; else : > "$dir/no-apache-conf"; fi
  if [[ -f "$APACHE_POLLING_CONF" ]]; then cp -a "$APACHE_POLLING_CONF" "$dir/apache-polling.conf"; else : > "$dir/no-apache-polling"; fi
  if [[ -f "$SERVICE_FILE" ]]; then cp -a "$SERVICE_FILE" "$dir/service"; else : > "$dir/no-service"; fi
  if [[ -f "$TIMER_FILE" ]]; then cp -a "$TIMER_FILE" "$dir/timer"; else : > "$dir/no-timer"; fi
  for relative in "${OBSOLETE_RELATIVE[@]}"; do
    if [[ -L "$APP_DIR/$relative" ]]; then
      fail "Unsafe legacy symlink found: $APP_DIR/$relative"
    elif [[ -f "$APP_DIR/$relative" ]]; then
      install -d -o root -g root -m 0700 "$dir/obsolete/$(dirname "$relative")"
      cp -a "$APP_DIR/$relative" "$dir/obsolete/$relative"
    fi
  done
  [[ -L "/etc/apache2/conf-enabled/${APACHE_CONF_NAME}.conf" ]] && : > "$dir/apache-enabled"
  [[ -L "/etc/apache2/conf-enabled/${APACHE_POLLING_NAME}.conf" ]] && : > "$dir/apache-polling-enabled"
  systemctl is-enabled --quiet asl3-node-audit.timer 2>/dev/null && : > "$dir/timer-enabled"
  chmod -R go-rwx "$dir"
  printf '%s' "$dir"
}

if [[ "$ACTION" == "uninstall" ]]; then
  [[ -d "$APP_DIR" && ! -L "$APP_DIR" ]] || fail "Application directory not found: $APP_DIR"
  backup="$(make_backup)"
  tar --exclude='.git' -C /var/www/html -czf "$backup/application-before-uninstall.tar.gz" asl3_node_audit
  chmod 0600 "$backup/application-before-uninstall.tar.gz"
  systemctl disable --now asl3-node-audit.timer >/dev/null 2>&1 || true
  systemctl stop asl3-node-audit.service >/dev/null 2>&1 || true
  rm -f "$SERVICE_FILE" "$TIMER_FILE"
  systemctl daemon-reload
  a2disconf "$APACHE_CONF_NAME" >/dev/null 2>&1 || true
  a2disconf "$APACHE_POLLING_NAME" >/dev/null 2>&1 || true
  rm -f "$APACHE_CONF" "$APACHE_POLLING_CONF"
  apache2ctl configtest >/dev/null || fail "Apache configuration failed after removing Node Audit confs. Backup: $backup"
  systemctl reload apache2.service
  rm -rf --one-file-system "$APP_DIR"
  ok "ASL3 Node Audit uninstalled. Protected backup: $backup"
  exit 0
fi

[[ "$ACTION" == "install" ]] || fail "Unsupported action."
[[ -d "$APP_DIR" && ! -L "$APP_DIR" ]] || fail "Expected repository at $APP_DIR"
[[ "$(cd "$(dirname "$0")" && pwd -P)" == "$APP_DIR" ]] || fail "Run the installer from $APP_DIR"
for dir in public src bin; do
  [[ -d "$APP_DIR/$dir" && ! -L "$APP_DIR/$dir" ]] || fail "Missing or unsafe application directory: $APP_DIR/$dir"
done
for runtime in run run/web run/auth; do
  [[ ! -L "$APP_DIR/$runtime" ]] || fail "Unsafe runtime symlink: $APP_DIR/$runtime"
done
for managed in "$APACHE_CONF" "$APACHE_POLLING_CONF" "$SERVICE_FILE" "$TIMER_FILE"; do
  [[ ! -L "$managed" ]] || fail "Unsafe managed-file symlink: $managed"
done
[[ ! -L "$BACKUP_ROOT" ]] || fail "Unsafe backup-root symlink: $BACKUP_ROOT"

for cmd in bash php python3 sudo apache2ctl a2enconf a2disconf systemctl install awk sed grep sort tar flock curl ip apt apt-cache apt-get; do
  command -v "$cmd" >/dev/null 2>&1 || fail "Required command is missing: $cmd"
done
id "$WEB_USER" >/dev/null 2>&1 || fail "Web user does not exist: $WEB_USER"
[[ -x /usr/sbin/asterisk ]] || fail "Asterisk was not found at /usr/sbin/asterisk."

required_files=(
  VERSION README.md .gitignore config.ini.example setup_asl3_node_audit.sh
  public/index.php public/login.php public/logout.php public/data.php public/live.php
  public/app.js public/security-live.js public/full-audit-live.js public/style.css
  src/auth.php src/node_identity.php src/apt_security.py src/monitor_engine.py
  bin/asl3-node-audit.sh bin/audit_monitor.py bin/security_monitor.py bin/monitor_runner.py bin/full_audit.py
)
for relative in "${required_files[@]}"; do
  [[ -f "$APP_DIR/$relative" && ! -L "$APP_DIR/$relative" ]] || fail "Missing or unsafe required file: $APP_DIR/$relative"
done

bash -n "$APP_DIR/setup_asl3_node_audit.sh"
bash -n "$APP_DIR/bin/asl3-node-audit.sh"
while IFS= read -r php_file; do php -l "$php_file" >/dev/null || fail "PHP syntax failed: $php_file"; done < <(find "$APP_DIR/public" "$APP_DIR/src" -type f -name '*.php' -print | sort)
while IFS= read -r py_file; do python3 -m py_compile "$py_file" || fail "Python syntax failed: $py_file"; done < <(find "$APP_DIR/bin" "$APP_DIR/src" -type f -name '*.py' -print | sort)
find "$APP_DIR" -type d -name __pycache__ -prune -exec rm -rf {} +
if command -v node >/dev/null 2>&1; then
  while IFS= read -r js_file; do node --check "$js_file" >/dev/null || fail "JavaScript syntax failed: $js_file"; done < <(find "$APP_DIR/public" -type f -name '*.js' -print | sort)
fi
python3 "$APP_DIR/bin/monitor_runner.py" --self-test >/dev/null || fail "Security monitor self-test failed."
python3 "$APP_DIR/bin/full_audit.py" --self-test >/dev/null || fail "Full audit parser self-test failed."

backup="$(make_backup)"
rollback_armed=1
cleanup() {
  local rc=$?
  trap - EXIT
  if [[ $rc -ne 0 && ${rollback_armed:-0} -eq 1 ]]; then
    echo "[WARN] Setup failed; restoring installer-managed configuration from $backup" >&2
    restore_backup "$backup" || true
  fi
  exit "$rc"
}
trap cleanup EXIT

# Prevent the timer from starting a cycle while setup is changing permissions/files.
systemctl stop asl3-node-audit.timer >/dev/null 2>&1 || true
for _ in {1..60}; do
  systemctl is-active --quiet asl3-node-audit.service || break
  sleep 1
done
systemctl is-active --quiet asl3-node-audit.service && fail "Existing audit service did not finish; setup stopped without forcing it down."

# Retire only the explicitly known old Node Audit files captured in the backup.
for relative in "${OBSOLETE_RELATIVE[@]}"; do
  [[ ! -L "$APP_DIR/$relative" ]] || fail "Unsafe legacy symlink found: $APP_DIR/$relative"
  rm -f "$APP_DIR/$relative"
done
rmdir "$APP_DIR/docs" 2>/dev/null || true

if [[ ! -f "$CONFIG_FILE" ]]; then
  install -o root -g "$WEB_GROUP" -m 0640 "$CONFIG_EXAMPLE" "$CONFIG_FILE"
fi
[[ ! -L "$CONFIG_FILE" ]] || fail "config.ini must not be a symlink."
remove_obsolete_https_host "$CONFIG_FILE"

node="$(get_key MYNODE "$CONFIG_FILE")"
if [[ ! "$node" =~ ^[0-9]{4,7}$ ]]; then
  detected="$(detect_node || true)"
  if [[ "$detected" =~ ^[0-9]{4,7}$ ]]; then
    set_key MYNODE "\"$detected\"" "$CONFIG_FILE"
    node="$detected"
  fi
fi

set_key ASL3_NODE_AUDIT_ADMIN_USER '"admin"' "$CONFIG_FILE"
[[ "$(get_key ASL3_NODE_AUDIT_AUTH_ENABLED "$CONFIG_FILE")" =~ ^[01]$ ]] || set_key ASL3_NODE_AUDIT_AUTH_ENABLED "0" "$CONFIG_FILE"
if ! grep -qE '^[[:space:]]*ASL3_NODE_AUDIT_ADMIN_PASSWORD_HASH[[:space:]]*=' "$CONFIG_FILE"; then
  set_key ASL3_NODE_AUDIT_ADMIN_PASSWORD_HASH '""' "$CONFIG_FILE"
fi
auth_enabled="$(get_key ASL3_NODE_AUDIT_AUTH_ENABLED "$CONFIG_FILE")"
saved_hash="$(get_key ASL3_NODE_AUDIT_ADMIN_PASSWORD_HASH "$CONFIG_FILE")"
if [[ -n "$saved_hash" ]] && ! valid_password_hash "$saved_hash"; then
  fail "config.ini contains an invalid administrator password hash. Run --set-admin-password to replace it."
fi
if [[ "$auth_enabled" == "1" && -z "$saved_hash" ]]; then
  fail "Application login is enabled but no password hash exists. Run --set-admin-password."
fi
unset saved_hash

# Source is root-owned and never web-writable.
chown root:root "$APP_DIR"
chmod 0755 "$APP_DIR"
find "$APP_DIR/public" -type d -exec chown root:root {} + -exec chmod 0755 {} +
find "$APP_DIR/public" -type f -exec chown root:root {} + -exec chmod 0644 {} +
install -d -o root -g "$WEB_GROUP" -m 0750 "$APP_DIR/src"
find "$APP_DIR/src" -type d -exec chown root:"$WEB_GROUP" {} + -exec chmod 0750 {} +
find "$APP_DIR/src" -type f -exec chown root:root {} + -exec chmod 0640 {} +
find "$APP_DIR/src" -type f -name '*.php' -exec chown root:"$WEB_GROUP" {} + -exec chmod 0640 {} +
install -d -o root -g root -m 0750 "$APP_DIR/bin"
find "$APP_DIR/bin" -type f -exec chown root:root {} + -exec chmod 0640 {} +
chmod 0750 "$APP_DIR/bin/asl3-node-audit.sh" "$APP_DIR/bin/audit_monitor.py" "$APP_DIR/bin/security_monitor.py" "$APP_DIR/bin/monitor_runner.py" "$APP_DIR/bin/full_audit.py"
chown root:root "$APP_DIR/setup_asl3_node_audit.sh" "$APP_DIR/README.md" "$APP_DIR/VERSION" "$APP_DIR/config.ini.example" "$APP_DIR/.gitignore" 2>/dev/null || true
chmod 0755 "$APP_DIR/setup_asl3_node_audit.sh"
chmod 0644 "$APP_DIR/README.md" "$APP_DIR/VERSION" "$APP_DIR/config.ini.example" "$APP_DIR/.gitignore" 2>/dev/null || true
chown root:"$WEB_GROUP" "$CONFIG_FILE"
chmod 0640 "$CONFIG_FILE"

# Private runtime: Apache can traverse run/, read only sanitized run/web feeds,
# and write only its bounded login-rate-limit directory.
install -d -o root -g "$WEB_GROUP" -m 0710 "$APP_DIR/run"
install -d -o root -g "$WEB_GROUP" -m 2750 "$APP_DIR/run/web"
install -d -o "$WEB_USER" -g "$WEB_GROUP" -m 0700 "$APP_DIR/run/auth"
find "$APP_DIR/run" -maxdepth 1 -type f -exec chown root:root {} + -exec chmod 0600 {} + 2>/dev/null || true
find "$APP_DIR/run/web" -maxdepth 1 -type f -exec chown root:"$WEB_GROUP" {} + -exec chmod 0640 {} + 2>/dev/null || true
find "$APP_DIR/run/auth" -maxdepth 1 -type f -exec chown "$WEB_USER":"$WEB_GROUP" {} + -exec chmod 0600 {} + 2>/dev/null || true

apache_tmp="$(mktemp)"
cat > "$apache_tmp" <<APACHE
# Managed by setup_asl3_node_audit.sh. ASL3 Node Audit only.
Alias /asl3_node_audit $APP_DIR/public

<Directory "$APP_DIR">
    Options -Indexes -FollowSymLinks -MultiViews
    AllowOverride None
    Require all denied
</Directory>

<Directory "$APP_DIR/public">
    Options -Indexes -FollowSymLinks -MultiViews
    AllowOverride None
    DirectoryIndex index.php
    Require all granted
</Directory>
APACHE
install -o root -g root -m 0644 "$apache_tmp" "$APACHE_CONF"
rm -f "$apache_tmp"

poll_tmp="$(mktemp)"
cat > "$poll_tmp" <<'APACHE'
# Managed by setup_asl3_node_audit.sh.
# Marks only successful high-frequency Node Audit polling when the host's
# existing CustomLog expression honors dontlog_app_polling_200.
SetEnvIf Request_URI "^/asl3_node_audit/(live\.php|data\.php)$" dontlog_app_polling_200=1
APACHE
install -o root -g root -m 0644 "$poll_tmp" "$APACHE_POLLING_CONF"
rm -f "$poll_tmp"
a2enconf "$APACHE_CONF_NAME" >/dev/null
a2enconf "$APACHE_POLLING_NAME" >/dev/null
apache2ctl configtest >/dev/null || fail "Apache rejected the ASL3 Node Audit configuration."
systemctl reload apache2.service || fail "Apache reload failed."

cat > "$SERVICE_FILE" <<EOF_SERVICE
[Unit]
Description=ASL3 Node Audit monitoring
After=network-online.target
Wants=network-online.target
ConditionPathExists=$APP_DIR/bin/audit_monitor.py

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/python3 $APP_DIR/bin/audit_monitor.py
TimeoutStartSec=900
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$APP_DIR/run /var/lib/apt/lists /var/cache/apt/archives /var/lib/apt /var/lib/dpkg
ProtectHome=true
EOF_SERVICE
chmod 0644 "$SERVICE_FILE"
chown root:root "$SERVICE_FILE"

cat > "$TIMER_FILE" <<'EOF_TIMER'
[Unit]
Description=ASL3 Node Audit scheduled monitoring

[Timer]
OnBootSec=2min
OnUnitInactiveSec=60s
AccuracySec=10s
Unit=asl3-node-audit.service
Persistent=false

[Install]
WantedBy=timers.target
EOF_TIMER
chmod 0644 "$TIMER_FILE"
chown root:root "$TIMER_FILE"
systemctl daemon-reload

# Permissions and read/write boundaries before the first monitor run.
sudo -u "$WEB_USER" test -r "$CONFIG_FILE" || fail "$WEB_USER cannot read config.ini"
sudo -u "$WEB_USER" test -r "$APP_DIR/src/auth.php" || fail "$WEB_USER cannot read src/auth.php"
sudo -u "$WEB_USER" test ! -w "$APP_DIR/public" || fail "public/ must not be writable by $WEB_USER"
sudo -u "$WEB_USER" test ! -w "$APP_DIR/src" || fail "src/ must not be writable by $WEB_USER"
sudo -u "$WEB_USER" test -w "$APP_DIR/run/auth" || fail "run/auth must be writable by $WEB_USER"
sudo -u "$WEB_USER" test ! -w "$APP_DIR/run/web" || fail "run/web must not be writable by $WEB_USER"

echo "[INFO] Running initial Node Audit checks. This may take a few minutes on slower systems..."
systemctl start asl3-node-audit.service || fail "Initial ASL3 Node Audit monitor run failed."
echo "[OK] Initial Node Audit checks completed."
result="$(systemctl show asl3-node-audit.service -p Result --value)"
status="$(systemctl show asl3-node-audit.service -p ExecMainStatus --value)"
[[ "$result" == "success" && "$status" == "0" ]] || fail "Initial monitor result was $result/$status"
systemctl enable --now asl3-node-audit.timer >/dev/null

# Local route checks. HTTP is preferred; HTTPS is a fallback. No hostname setting is required.
curl_code() {
  local url="$1"; shift
  curl -sS --noproxy '*' --connect-timeout 3 --max-time 8 "$@" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true
}
base=""
for try in "http://127.0.0.1" "https://127.0.0.1"; do
  extra=(); [[ "$try" == https:* ]] && extra=(-k)
  [[ "$(curl_code "$try/asl3_node_audit/" "${extra[@]}")" == "200" ]] && { base="$try"; break; }
done
[[ -n "$base" ]] || fail "Local Node Audit route did not return HTTP 200."
extra=(); [[ "$base" == https:* ]] && extra=(-k)
auth_enabled="$(get_key ASL3_NODE_AUDIT_AUTH_ENABLED "$CONFIG_FILE")"
[[ "$(curl_code "$base/asl3_node_audit/live.php" "${extra[@]}")" == "200" ]] || fail "live.php read-only view is unavailable."
for private in config.ini src/auth.php run/web/security-feed.json; do
  code="$(curl_code "$base/asl3_node_audit/$private" "${extra[@]}")"
  [[ "$code" == "403" || "$code" == "404" ]] || fail "Private path is exposed: $private returned HTTP $code"
done
[[ "$(curl_code "$base/asl3_node_audit/data.php?feed=security" "${extra[@]}")" == "200" ]] || fail "Security feed is not available."
[[ "$(curl_code "$base/asl3_node_audit/data.php?feed=full" "${extra[@]}")" == "200" ]] || fail "Full audit feed is not available."

node="$(get_key MYNODE "$CONFIG_FILE")"
rollback_armed=0
trap - EXIT
ok "ASL3 Node Audit setup complete."
echo "Version: $(tr -d '\r\n' < "$APP_DIR/VERSION")"
if [[ "$node" =~ ^[0-9]{4,7}$ ]]; then echo "Local node: $node"; else echo "MYNODE was not detected unambiguously. Set it in $CONFIG_FILE and run setup again."; fi
echo "Config: $CONFIG_FILE"
echo "Timer: asl3-node-audit.timer"
echo "Protected setup backup: $backup"
show_access_info
show_auth_status
