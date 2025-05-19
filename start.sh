#!/bin/bash

# MTProto Proxy Whitelist Installer with Stream, PHP, and Secure Access
# For Ubuntu with NGINX + PHP + Stream + HTTPS support and ufw fail2ban
# Supports both one-time and 5-minute tokens

# === Variables ===
NGINX_CONF_DIR="/etc/nginx"
WHITE_LIST_FILE="/etc/nginx/whitelist.txt"
PASSWORD_FILE="/etc/nginx/.password"
USED_TOKENS_FILE="/etc/nginx/used_tokens.txt"
WEB_DIR="/var/www/html"
NGINX_STREAM_CONF="/etc/nginx/nginx.conf"
NGINX_SITES_DIR="/etc/nginx/sites-available"
NGINX_SITES_LINK="/etc/nginx/sites-enabled/whitelist_gateway"
WHITELIST_SITE_CONF="$NGINX_SITES_DIR/whitelist_gateway"
STREAM_CONF_FILE="/etc/nginx/stream.d/mtproto.conf"

DOMAIN=""
PROXY_PORT=""
NGINX_PORT=""

# === Helper Functions ===
check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Run as root."
    exit 1
  fi
}
setup_ufw_rules() {
   
    ufw limit ssh
    ufw allow http/tcp
    ufw allow https/tcp
    ufw allow 8443/tcp
    ufw --force enable
}
create_password() {
  echo "=== Create/Change Password ==="
  read -p "Enter new password for IP whitelist page: " -s PASSWORD
  echo
  read -p "Confirm new password: " -s PASSWORD_CONFIRM
  echo
  if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
    echo "Passwords do not match!"
    return
  fi
  SALT=$(openssl rand -hex 8)
  HASHED_PASSWORD=$(echo -n "$PASSWORD$SALT" | sha256sum | awk '{print $1}')
  echo "$HASHED_PASSWORD:$SALT" > "$PASSWORD_FILE"
  chmod 600 "$PASSWORD_FILE"
  chown www-data:www-data "$PASSWORD_FILE"
  echo "Password updated successfully."
}

install_nginx_with_stream() {
  echo "[+] Installing NGINX with stream module..."
  apt update
  apt install -y ufw fail2ban nginx libnginx-mod-stream
  mkdir -p /etc/nginx/stream.d
touch /etc/nginx/stream.d/mtproto.conf

if ! grep -q "stream {" "$NGINX_STREAM_CONF"; then
  sed -i "/http {/i \\
stream {\n    include /etc/nginx/stream.d/mtproto.conf;\n\n}" "$NGINX_STREAM_CONF"
fi

  mkdir -p /etc/nginx/stream.d
}

install_php() {
  echo "[+] Installing PHP..."
  apt install -y php php-cli php-fpm php-curl
}

install_certbot() {
  echo "[+] Installing Certbot for HTTPS..."
  apt install -y certbot python3-certbot-nginx
}

create_files_and_permissions() {
  echo "[+] Creating necessary files and setting permissions..."
  mkdir -p "$WEB_DIR"
  touch "$WHITE_LIST_FILE"
  chmod 644 "$WHITE_LIST_FILE"

  touch "$USED_TOKENS_FILE"
  chmod 600 "$USED_TOKENS_FILE"

  if [ ! -f "$PASSWORD_FILE" ]; then
    read -p "Enter password for IP whitelist page: " -s PASSWORD
    echo
    SALT=$(openssl rand -hex 8)
    HASHED_PASSWORD=$(echo -n "$PASSWORD$SALT" | sha256sum | awk '{print $1}')
    echo "$HASHED_PASSWORD:$SALT" > "$PASSWORD_FILE"
    chmod 600 "$PASSWORD_FILE"
  else
    # Read existing password hash and salt
    local passdata
    passdata=$(cat "$PASSWORD_FILE")
    HASHED_PASSWORD="${passdata%%:*}"
    SALT="${passdata##*:}"
  fi

  # PHP script to accept one-time or 5-min token
  cat > "$WEB_DIR/post.php" <<'EOF'
<?php
function is_password_correct($pass, $salt, $stored_hash) {
    return hash('sha256', $pass . $salt) === $stored_hash;
}

function token_used($token, $used_tokens_file) {
    $used_tokens = file_exists($used_tokens_file) ? file($used_tokens_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    return in_array($token, $used_tokens);
}

function mark_token_used($token, $used_tokens_file) {
    file_put_contents($used_tokens_file, $token . "\n", FILE_APPEND | LOCK_EX);
}

// Validate one-time token: token = base64(timestamp:hash)
// timestamp not older than 5 minutes (300 seconds)
// and hash = sha256(secret + timestamp)
function is_one_time_token_valid($token, $secret, $used_tokens_file) {
    if (token_used($token, $used_tokens_file)) return false;
    $decoded = base64_decode($token, true);
    if (!$decoded) return false;
    $parts = explode(':', $decoded);
    if (count($parts) !== 2) return false;
    list($timestamp, $hash) = $parts;
    if (!ctype_digit($timestamp)) return false;
    if (time() - intval($timestamp) > 300) return false; // 5 min expiry
    $check_hash = hash('sha256', $secret . $timestamp);
    if (!hash_equals($check_hash, $hash)) return false;
    return true;
}

// Validate 5-minute token: token = base64(timestamp:hash)
// timestamp not older than 5 minutes (300 seconds)
// and hash = sha256(secret + timestamp)
function is_five_min_token_valid($token, $secret) {
    $decoded = base64_decode($token, true);
    if (!$decoded) return false;
    $parts = explode(':', $decoded);
    if (count($parts) !== 2) return false;
    list($timestamp, $hash) = $parts;
    if (!ctype_digit($timestamp)) return false;
    if (time() - intval($timestamp) > 300) return false; // 5 min expiry
    $check_hash = hash('sha256', $secret . $timestamp);
    if (!hash_equals($check_hash, $hash)) return false;
    return true;
}

// Main
$password_file = "/etc/nginx/.password";
$used_tokens_file = "/etc/nginx/used_tokens.txt";
$whitelist_file = "/etc/nginx/whitelist.txt";

list($stored_hash, $salt) = explode(":", trim(file_get_contents($password_file)));


if (!isset($_GET['pass']) || empty($_GET['pass'])) {
    http_response_code(400);
    exit("Missing required parameter: pass");
}
$pass = base64_decode(strtr($_GET['pass'], '_-', '/+'));

$token = isset($_GET['token']) ? $_GET['token'] : '';
if (empty($token)) {
    http_response_code(400);
    exit("Missing required parameter: token");
}

if (!is_password_correct($pass, $salt, $stored_hash)) {
    http_response_code(403);
    exit("Access denied: Incorrect password.");
}

$secret = hash('sha256', $pass . $salt);

if (is_one_time_token_valid($token, $secret, $used_tokens_file)) {
    // one-time token is valid and unused, mark used
    mark_token_used($token, $used_tokens_file);
} elseif (is_five_min_token_valid($token, $secret)) {
    // 5-min token valid, no marking needed (can be reused within 5 mins)
} else {
    http_response_code(403);
    exit("Access denied: Invalid or expired token.");
}

$ip = $_SERVER['REMOTE_ADDR'];
$entry = "allow $ip;\n";

$existing = file_exists($whitelist_file) ? file($whitelist_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

if (!in_array(trim($entry), $existing)) {
    file_put_contents($whitelist_file, $entry, FILE_APPEND | LOCK_EX);
    echo "IP $ip added to whitelist.";
} else {
    echo "IP $ip is already whitelisted.";
}
?>
EOF

  chmod 644 "$WEB_DIR/post.php"
}

setup_nginx_site() {
  read -p "Enter your domain (must already point to this server): " DOMAIN
  read -p "Enter your Telegram proxy port (e.g. 48500): " PROXY_PORT
  read -p "Enter NGINX whitelist gateway port (e.g. 8443): " NGINX_PORT

  if [[ -z "$DOMAIN" ]]; then
        echo "[âœ—] Domain cannot be empty."
        exit 1
    fi

    # Detect PHP version like 8.1 or 8.2 etc.
    if command -v php >/dev/null 2>&1; then
        PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
    else
        echo "[âœ—] PHP is not installed or not in PATH."
        exit 1
    fi

  cat > "$WHITELIST_SITE_CONF" <<EOF
server {
  listen 80;
  server_name $DOMAIN;

  root $WEB_DIR;
  index index.php index.html;

  location ~ \.php\$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php-fpm.sock;
  }

  location / {
    try_files \$uri \$uri/ =404;
  }
}
EOF


  ln -sf "$WHITELIST_SITE_CONF" "$NGINX_SITES_LINK"
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m admin@$DOMAIN || true
  systemctl reload nginx
# 3. Overwrite or update the HTTPS server block as you want
cat > "$WHITELIST_SITE_CONF" <<EOF
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    root $WEB_DIR;
    index index.php index.html index.htm;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers HIGH:!aNULL:!MD5;
    server_tokens off;
    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php$PHP_VERSION-fpm.sock;
    }

    location ~ /\.ht {
        deny all;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}
EOF
chmod 750 /etc/nginx
systemctl reload nginx
  cat > /etc/nginx/stream.d/mtproto.conf <<EOF

server {
    listen $NGINX_PORT;
    proxy_pass 127.0.0.1:$PROXY_PORT;
    allow 127.0.0.1;
    include /etc/nginx/whitelist.txt;
    deny all;
}
EOF
}

fix_permissions() {
  echo "[*] Fixing file and directory permissions..."

  chown -R www-data:www-data "$WEB_DIR"
  chown www-data:www-data "$PASSWORD_FILE"
  chown www-data:www-data "$WHITE_LIST_FILE"
  chown www-data:www-data "$USED_TOKENS_FILE"

  chmod 644 "$WEB_DIR"/*.php
  chmod 600 "$PASSWORD_FILE"
  chmod 600 "$WHITE_LIST_FILE"
  chmod 600 "$USED_TOKENS_FILE"

  chmod 755 /etc/nginx
  chmod 755 /var/www
  chmod 755 "$WEB_DIR"
  sudo -u www-data test -r "$PASSWORD_FILE" && echo "[âœ“] www-data can read password file"
  sudo -u www-data test -w "$WHITE_LIST_FILE" && echo "[âœ“] www-data can write to whitelist"
  # Path to the config file
  STREAM_CONF_FILE="/etc/nginx/stream.d/mtproto.conf"

  # Ensure the directory exists
  mkdir -p /etc/nginx/stream.d

  # Create the file if it doesn't exist
  touch "$STREAM_CONF_FILE"

  # Set secure permissions
  chown root:root "$STREAM_CONF_FILE"
  chmod 644 "$STREAM_CONF_FILE"

  echo "[+] Permissions fixed successfully."
}

generate_token_url() {
  if [ ! -f "$PASSWORD_FILE" ]; then
    echo "Password file not found! Please install first."
    return
  fi

  read -p "Enter your password for whitelist page: " -s PASS_INPUT
  echo

  read -p "Enter your domain (used in URL): " DOMAIN
  if [[ -z "$DOMAIN" ]]; then
    echo "Domain is required!"
    return
  fi

  # Read salt and hashed password from file
  local raw
  raw=$(cat "$PASSWORD_FILE")
  local HASHED_PASSWORD="${raw%%:*}"
  local SALT="${raw##*:}"

  # Verify password
  SECRET=$(echo -n "$PASS_INPUT$SALT" | sha256sum | awk '{print $1}')
  if [ "$SECRET" != "$HASHED_PASSWORD" ]; then
    echo "Password incorrect!"
    return
  fi

  # Generate 5-minute token URL
  TIMESTAMP_5MIN=$(date +%s)
  TOKEN_HASH_5MIN=$(echo -n "${SECRET}${TIMESTAMP_5MIN}" | sha256sum | awk '{print $1}')
  TOKEN_RAW_5MIN="${TIMESTAMP_5MIN}:${TOKEN_HASH_5MIN}"
  TOKEN_5MIN=$(echo -n "$TOKEN_RAW_5MIN" | base64)

  # Generate one-time token URL (same format, but used once)
  TIMESTAMP_OT=$(date +%s)
  TOKEN_HASH_OT=$(echo -n "${SECRET}${TIMESTAMP_OT}" | sha256sum | awk '{print $1}')
  TOKEN_RAW_OT="${TIMESTAMP_OT}:${TOKEN_HASH_OT}"
  TOKEN_OT=$(echo -n "$TOKEN_RAW_OT" | base64)

  echo
  echo "Your access URLs:"
  echo "1) One-time token URL (valid for single use within 5 minutes):"
 PASS_B64=$(echo -n "$PASS_INPUT" | base64 | tr -d '=' | tr '/+' '_-')
  echo "https://$DOMAIN/post.php?pass=$PASS_B64&token=$TOKEN_OT"

  echo
  echo "2) 5-minute token URL (valid for 5 minutes, reusable):"
  PASS_B64=$(echo -n "$PASS_INPUT" | base64 | tr -d '=' | tr '/+' '_-')
  echo "https://$DOMAIN/post.php?pass=$PASS_B64&token=$TOKEN_5MIN"

  echo "NOTE: Use one-time token once only, 5-minute token multiple times within 5 mins."
}
check_files_and_permissions() {
  echo "[*] Verifying file creation and permissions..."

  local success=true

  # List of expected files
  declare -A files=(
    ["$WEB_DIR/post.php"]="644"
    ["$PASSWORD_FILE"]="600"
    ["$WHITE_LIST_FILE"]="600"
    ["$USED_TOKENS_FILE"]="600"
  )

  for file in "${!files[@]}"; do
    expected_perm=${files[$file]}

    # Check if file exists
    if [[ ! -f "$file" ]]; then
      echo "[âœ—] Missing file: $file"
      success=false
      continue
    fi

    # Check permissions
    actual_perm=$(stat -c "%a" "$file")
    if [[ "$actual_perm" != "$expected_perm" ]]; then
      echo "[âœ—] Incorrect permissions on $file (Expected: $expected_perm, Got: $actual_perm)"
      success=false
    else
      echo "[âœ“] Permissions OK on $file ($expected_perm)"
    fi

    # Check ownership
    owner=$(stat -c "%U" "$file")
    group=$(stat -c "%G" "$file")
    if [[ "$owner" != "www-data" || "$group" != "www-data" ]]; then
      echo "[âœ—] Incorrect ownership on $file (Expected: www-data:www-data, Got: $owner:$group)"
      success=false
    else
      echo "[âœ“] Ownership OK on $file (www-data:www-data)"
    fi
  done

  # Check directory
  if [[ ! -d "$WEB_DIR" ]]; then
    echo "[âœ—] Missing web directory: $WEB_DIR"
    success=false
  else
    dir_perm=$(stat -c "%a" "$WEB_DIR")
    if [[ "$dir_perm" != "755" ]]; then
      echo "[âœ—] Incorrect permissions on $WEB_DIR (Expected: 755, Got: $dir_perm)"
      success=false
    else
      echo "[âœ“] Web directory permissions OK ($dir_perm)"
    fi
  fi

  if [[ "$success" = true ]]; then
    echo "[+] All files verified successfully."
  else
    echo "[!] Some files are missing or have incorrect permissions."
  fi
}

show_menu() {
check_root
  clear
  echo "==== MTProto Proxy Whitelist Installer ===="
  echo "1) Install everything (NGINX, PHP, whitelist system)"
  echo "2) Generate access URL with tokens (one-time & 5-min tokens)"
  echo "3) Fix permissions"
  echo "4) Change WhiteList Password/hashed/salt
  echo "5) Uninstall (remove all installed components)"
  echo "0) Exit"
  echo "==========================================="
  read -p "Choose an option: " choice
  case $choice in
    1)
  check_root
      install_nginx_with_stream
      install_php
      install_certbot
      create_files_and_permissions
      setup_nginx_site
      fix_permissions
      check_files_and_permissions
      setup_ufw_rules
# Final success message
echo "[*] Installation complete."

      ;;
    2)
      generate_token_url
      ;;
    3)
      fix_permissions
      ;;
    4)
      create_password
      ;;

    5)
      echo "Uninstalling..."
      systemctl stop nginx
      apt remove -y nginx php-fpm php libnginx-mod-stream certbot python3-certbot-nginx
      rm -rf "$WEB_DIR/post.php" "$WHITE_LIST_FILE" "$USED_TOKENS_FILE" "$PASSWORD_FILE"
      rm -f "$WHITELIST_SITE_CONF" "$NGINX_SITES_LINK"
      rm -f /etc/nginx/stream.d/mtproto.conf
      systemctl restart nginx
      echo "Uninstall complete."
      ;;
    0)
      echo "Bye."
      exit 0
      ;;
    *)
      echo "Invalid option."
      ;;
  esac
  read -p "Press Enter to continue..."
  show_menu
}

show_menu
