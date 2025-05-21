#!/bin/bash

# ==============================================
# MTProto Proxy Whitelist Installer
# Enhanced Version with Security, Error Handling
# and Performance Optimizations
# ==============================================

# Configuration
CONFIG_FILE="/etc/mtproxy-whitelist.conf"
LOG_FILE="/var/log/mtproxy-whitelist.log"
NGINX_CONF_DIR="/etc/nginx"
WHITE_LIST_FILE="$NGINX_CONF_DIR/whitelist.txt"
PASSWORD_FILE="$NGINX_CONF_DIR/.password"
USED_TOKENS_FILE="$NGINX_CONF_DIR/used_tokens.txt"
WEB_DIR="/var/www/html"
NGINX_STREAM_CONF="$NGINX_CONF_DIR/nginx.conf"
NGINX_SITES_DIR="$NGINX_CONF_DIR/sites-available"
NGINX_SITES_LINK="$NGINX_CONF_DIR/sites-enabled/whitelist_gateway"
WHITELIST_SITE_CONF="$NGINX_SITES_DIR/whitelist_gateway"
STREAM_CONF_FILE="$NGINX_CONF_DIR/stream.d/mtproto.conf"
BACKUP_DIR="/var/backups/mtproxy-whitelist"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Initialize variables
DOMAIN=""
PROXY_PORT=""
NGINX_PORT=""
PHP_VERSION=""

# ==============================================
# HELPER FUNCTIONS
# ==============================================

# Logging function
log() {
  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Error handling function
error_exit() {
  log "${RED}ERROR: $1${NC}"
  exit 1
}

# Check if running as root
check_root() {
  if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run as root. Please use sudo."
  fi
}

# Validate port number
validate_port() {
  local port=$1
  if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
    error_exit "Invalid port number: $port. Must be between 1-65535."
  fi
}

# Validate domain name
validate_domain() {
  local domain=$1
  if [[ -z "$domain" ]]; then
    error_exit "Domain cannot be empty."
  fi
  
  # Simple domain validation regex
  if ! [[ "$domain" =~ ^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$ ]]; then
    error_exit "Invalid domain format: $domain"
  fi
}

# Validate password strength
validate_password() {
  local password=$1
  if [[ ${#password} -lt 12 ]]; then
    error_exit "Password must be at least 12 characters long."
  fi
}
install_ufw_if_missing() {
    if ! command -v ufw >/dev/null 2>&1; then
        echo "Installing ufw..."
        apt update && apt install ufw -y || error_exit "Failed to install ufw"
    fi
}
# Check dependencies
check_dependencies() {
  install_ufw_if_missing
  local dependencies=("curl" "openssl" "ufw" "systemctl")
  for dep in "${dependencies[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      error_exit "Missing required dependency: $dep"
    fi
  done
}

# Load configuration
load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE" || error_exit "Failed to load config file."
  fi
}

# Save configuration
save_config() {
  mkdir -p "$(dirname "$CONFIG_FILE")"
  cat > "$CONFIG_FILE" <<EOF
# MTProxy Whitelist Configuration
DOMAIN="$DOMAIN"
PROXY_PORT="$PROXY_PORT"
NGINX_PORT="$NGINX_PORT"
EOF
  chmod 600 "$CONFIG_FILE"
}

# Create backup
create_backup() {
  log "Creating backup of current configuration..."
  mkdir -p "$BACKUP_DIR"
  local timestamp=$(date +%Y%m%d-%H%M%S)
  local backup_file="$BACKUP_DIR/config-$timestamp.tar.gz"
  
  tar -czf "$backup_file" \
    "$WHITE_LIST_FILE" \
    "$PASSWORD_FILE" \
    "$USED_TOKENS_FILE" \
    "$NGINX_CONF_DIR" \
    "$WEB_DIR/post.php" 2>/dev/null
    
  if [[ $? -eq 0 ]]; then
    log "Backup created: ${GREEN}$backup_file${NC}"
  else
    log "${YELLOW}Warning: Backup creation failed${NC}"
  fi
}

# Check PHP version
get_php_version() {
  if command -v php >/dev/null 2>&1; then
    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
  else
    PHP_VERSION=""
  fi
}

# ==============================================
# INSTALLATION FUNCTIONS
# ==============================================

# Setup UFW firewall rules
setup_ufw_rules() {
  log "Configuring UFW firewall rules..."
  
  ufw --force reset || error_exit "Failed to reset UFW"
  ufw default deny incoming || error_exit "Failed to set UFW defaults"
  ufw default allow outgoing || error_exit "Failed to set UFW defaults"
  ufw limit ssh || error_exit "Failed to configure SSH in UFW"
  ufw allow http/tcp || error_exit "Failed to allow HTTP"
  ufw allow https/tcp || error_exit "Failed to allow HTTPS"
  
  if [[ -n "$NGINX_PORT" ]]; then
    ufw allow "$NGINX_PORT"/tcp || error_exit "Failed to allow NGINX port"
  fi
  
  ufw --force enable || error_exit "Failed to enable UFW"
  log "${GREEN}Firewall configured successfully${NC}"
}

# Install MTProto Proxy
install_mtproto_proxy() {
  log "Installing MTProto Proxy..."
  
  cd /opt || error_exit "Failed to change to /opt directory"
  
  # Download with retry logic
  local retries=3
  local success=false
  
  for ((i=1; i<=retries; i++)); do
    log "Downloading MTProto Proxy installer (attempt $i/$retries)..."
    if curl -o MTProtoProxyInstall.sh -L https://git.io/fjo34; then
      success=true
      break
    fi
    sleep 5
  done
  
  if [[ "$success" != true ]]; then
    error_exit "Failed to download MTProtoProxyInstall.sh after $retries attempts"
  fi
  
  chmod +x MTProtoProxyInstall.sh || error_exit "Failed to make installer executable"
  bash MTProtoProxyInstall.sh || error_exit "MTProto Proxy installation failed"
  
  log "${GREEN}MTProto Proxy installed successfully${NC}"
}

# Install NGINX with stream module
install_nginx_with_stream() {
  log "Installing NGINX with stream module..."
  
  apt update || error_exit "Failed to update package lists"
  apt install -y ufw fail2ban nginx libnginx-mod-stream || error_exit "Failed to install packages"
  
  mkdir -p /etc/nginx/stream.d || error_exit "Failed to create stream.d directory"
  touch "$STREAM_CONF_FILE" || error_exit "Failed to create stream config file"
  
  # Add stream block if not exists
  if ! grep -q "stream {" "$NGINX_STREAM_CONF"; then
    sed -i "/http {/i \\
stream {\\
    include /etc/nginx/stream.d/*.conf;\\
}" "$NGINX_STREAM_CONF" || error_exit "Failed to modify nginx.conf"
  fi
  
  log "${GREEN}NGINX installed successfully${NC}"
}

# Install PHP
install_php() {
  log "Installing PHP..."
  
  apt install -y php php-cli php-fpm php-curl || error_exit "Failed to install PHP packages"
  get_php_version
  
  log "${GREEN}PHP $PHP_VERSION installed successfully${NC}"
}

# Install Certbot
install_certbot() {
  log "Installing Certbot..."
  
  apt install -y certbot python3-certbot-nginx || error_exit "Failed to install Certbot"
  
  log "${GREEN}Certbot installed successfully${NC}"
}

# Create password file
create_password() {
  log "Creating password file..."
  
  while true; do
    read -p "Enter new password for IP whitelist page (min 12 chars): " -s PASSWORD
    echo
    if [[ ${#PASSWORD} -ge 12 ]]; then
      break
    fi
    echo -e "${YELLOW}Password must be at least 12 characters long.${NC}"
  done
  
  read -p "Confirm new password: " -s PASSWORD_CONFIRM
  echo
  
  if [[ "$PASSWORD" != "$PASSWORD_CONFIRM" ]]; then
    error_exit "Passwords do not match!"
  fi
  
  SALT=$(openssl rand -hex 8) || error_exit "Failed to generate salt"
  HASHED_PASSWORD=$(echo -n "$PASSWORD$SALT" | sha256sum | awk '{print $1}') || error_exit "Failed to hash password"
  
  echo "$HASHED_PASSWORD:$SALT" > "$PASSWORD_FILE" || error_exit "Failed to create password file"
  chmod 600 "$PASSWORD_FILE" || error_exit "Failed to set password file permissions"
  chown www-data:www-data "$PASSWORD_FILE" || error_exit "Failed to set password file ownership"
  
  log "${GREEN}Password file created successfully${NC}"
}

# Create necessary files and set permissions
create_files_and_permissions() {
  log "Creating files and setting permissions..."
  
  mkdir -p "$WEB_DIR" || error_exit "Failed to create web directory"
  touch "$WHITE_LIST_FILE" || error_exit "Failed to create whitelist file"
  chmod 644 "$WHITE_LIST_FILE" || error_exit "Failed to set whitelist file permissions"
  
  touch "$USED_TOKENS_FILE" || error_exit "Failed to create used tokens file"
  chmod 600 "$USED_TOKENS_FILE" || error_exit "Failed to set tokens file permissions"
  
  if [[ ! -f "$PASSWORD_FILE" ]]; then
    create_password
  else
    # Read existing password hash and salt
    local passdata
    passdata=$(cat "$PASSWORD_FILE") || error_exit "Failed to read password file"
    HASHED_PASSWORD="${passdata%%:*}"
    SALT="${passdata##*:}"
  fi
  
  # Create PHP script
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

function is_one_time_token_valid($token, $secret, $used_tokens_file) {
    if (token_used($token, $used_tokens_file)) return false;
    $decoded = base64_decode($token, true);
    if (!$decoded) return false;
    $parts = explode(':', $decoded);
    if (count($parts) !== 2) return false;
    list($timestamp, $hash) = $parts;
    if (!ctype_digit($timestamp)) return false;
    if (time() - intval($timestamp) > 2592000) return false; // 30 days expiry
    $check_hash = hash('sha256', $secret . $timestamp);
    if (!hash_equals($check_hash, $hash)) return false;
    return true;
}

function is_five_min_token_valid($token, $secret) {
    $decoded = base64_decode($token, true);
    if (!$decoded) return false;
    $parts = explode(':', $decoded);
    if (count($parts) !== 2) return false;
    list($timestamp, $hash) = $parts;
    if (!ctype_digit($timestamp)) return false;
    if (time() - intval($timestamp) > 900) return false; // 15 min expiry
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
    mark_token_used($token, $used_tokens_file);
} elseif (is_five_min_token_valid($token, $secret)) {
    // Valid token, continue
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

  chmod 644 "$WEB_DIR/post.php" || error_exit "Failed to set PHP file permissions"
  
  log "${GREEN}Files created and permissions set successfully${NC}"
}

# Setup NGINX site configuration
setup_nginx_site() {
  log "Configuring NGINX site..."
  
  while true; do
    read -p "Enter your domain (must already point to this server): " DOMAIN
    validate_domain "$DOMAIN" && break
  done
  
  while true; do
    read -p "Enter your Telegram proxy port (e.g., 48500): " PROXY_PORT
    validate_port "$PROXY_PORT" && break
  done
  
  while true; do
    read -p "Enter NGINX whitelist gateway port (e.g., 8443): " NGINX_PORT
    validate_port "$NGINX_PORT" && break
  done
  
  get_php_version
  if [[ -z "$PHP_VERSION" ]]; then
    error_exit "PHP version could not be detected"
  fi

  # Create HTTP server block
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

  # Create symlink
  ln -sf "$WHITELIST_SITE_CONF" "$NGINX_SITES_LINK" || error_exit "Failed to create NGINX symlink"
  
  # Obtain SSL certificate
  log "Obtaining SSL certificate..."
  if ! certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m admin@$DOMAIN; then
    log "${YELLOW}Certbot failed, continuing with self-signed certificate${NC}"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/ssl/private/nginx-selfsigned.key \
      -out /etc/ssl/certs/nginx-selfsigned.crt \
      -subj "/CN=$DOMAIN" || error_exit "Failed to create self-signed certificate"
  fi

  # Create HTTPS server block
  cat > "$WHITELIST_SITE_CONF" <<EOF
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    root $WEB_DIR;
    index index.php index.html index.htm;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/$DOMAIN/chain.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    server_tokens off;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php$PHP_VERSION-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
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

  # Create stream configuration
  mkdir -p "$(dirname "$STREAM_CONF_FILE")" || error_exit "Failed to create stream.d directory"
  cat > "$STREAM_CONF_FILE" <<EOF
server {
    listen $NGINX_PORT;
    proxy_pass 127.0.0.1:$PROXY_PORT;
    proxy_timeout 20m;
    proxy_connect_timeout 1s;
    
    allow 127.0.0.1;
    include $WHITE_LIST_FILE;
    deny all;
}
EOF

  # Set secure permissions
  chmod 750 /etc/nginx || error_exit "Failed to set NGINX directory permissions"
  systemctl reload nginx || error_exit "Failed to reload NGINX"
  
  save_config
  
  log "${GREEN}NGINX site configured successfully${NC}"
}

# Fix permissions
fix_permissions() {
  log "Fixing permissions..."
  
  chown -R www-data:www-data "$WEB_DIR" || error_exit "Failed to set web directory ownership"
  chown www-data:www-data "$PASSWORD_FILE" || error_exit "Failed to set password file ownership"
  chown www-data:www-data "$WHITE_LIST_FILE" || error_exit "Failed to set whitelist file ownership"
  chown www-data:www-data "$USED_TOKENS_FILE" || error_exit "Failed to set tokens file ownership"

  chmod 644 "$WEB_DIR"/*.php || error_exit "Failed to set PHP file permissions"
  chmod 600 "$PASSWORD_FILE" || error_exit "Failed to set password file permissions"
  chmod 600 "$WHITE_LIST_FILE" || error_exit "Failed to set whitelist file permissions"
  chmod 600 "$USED_TOKENS_FILE" || error_exit "Failed to set tokens file permissions"

  chmod 755 /etc/nginx || error_exit "Failed to set NGINX directory permissions"
  chmod 755 /var/www || error_exit "Failed to set www directory permissions"
  chmod 755 "$WEB_DIR" || error_exit "Failed to set web directory permissions"

  # Verify permissions
  sudo -u www-data test -r "$PASSWORD_FILE" || log "${YELLOW}Warning: www-data cannot read password file${NC}"
  sudo -u www-data test -w "$WHITE_LIST_FILE" || log "${YELLOW}Warning: www-data cannot write to whitelist${NC}"

  # Set stream config permissions
  chown root:root "$STREAM_CONF_FILE" || error_exit "Failed to set stream config ownership"
  chmod 644 "$STREAM_CONF_FILE" || error_exit "Failed to set stream config permissions"

  log "${GREEN}Permissions fixed successfully${NC}"
}

# Generate token URL
generate_token_url() {
  log "Generating access token URLs..."
  
  if [[ ! -f "$PASSWORD_FILE" ]]; then
    error_exit "Password file not found! Please install first."
  fi

  read -p "Enter your password for whitelist page: " -s PASS_INPUT
  echo

  if [[ -z "$DOMAIN" ]]; then
    read -p "Enter your domain (used in URL): " DOMAIN
    validate_domain "$DOMAIN"
  fi

  # Read salt and hashed password from file
  local raw
  raw=$(cat "$PASSWORD_FILE") || error_exit "Failed to read password file"
  local HASHED_PASSWORD="${raw%%:*}"
  local SALT="${raw##*:}"

  # Verify password
  SECRET=$(echo -n "$PASS_INPUT$SALT" | sha256sum | awk '{print $1}') || error_exit "Failed to generate secret"
  if [[ "$SECRET" != "$HASHED_PASSWORD" ]]; then
    error_exit "Password incorrect!"
  fi

  # Generate 15-minute token URL
  TIMESTAMP_5MIN=$(date +%s)
  TOKEN_HASH_5MIN=$(echo -n "${SECRET}${TIMESTAMP_5MIN}" | sha256sum | awk '{print $1}') || error_exit "Failed to generate token hash"
  TOKEN_RAW_5MIN="${TIMESTAMP_5MIN}:${TOKEN_HASH_5MIN}"
  TOKEN_5MIN=$(echo -n "$TOKEN_RAW_5MIN" | base64) || error_exit "Failed to encode token"

  # Generate one-time token URL
  TIMESTAMP_OT=$(date +%s)
  TOKEN_HASH_OT=$(echo -n "${SECRET}${TIMESTAMP_OT}" | sha256sum | awk '{print $1}') || error_exit "Failed to generate token hash"
  TOKEN_RAW_OT="${TIMESTAMP_OT}:${TOKEN_HASH_OT}"
  TOKEN_OT=$(echo -n "$TOKEN_RAW_OT" | base64) || error_exit "Failed to encode token"

  # Generate URLs
  PASS_B64=$(echo -n "$PASS_INPUT" | base64 | tr -d '=' | tr '/+' '_-') || error_exit "Failed to encode password"
  
  echo -e "\n${GREEN}Your access URLs:${NC}"
  echo -e "1) ${BLUE}One-time token URL${NC} (valid for single use within 30 days):"
  echo "https://$DOMAIN/post.php?pass=$PASS_B64&token=$TOKEN_OT"

  echo -e "\n2) ${BLUE}15-minute token URL${NC} (valid for 15 minutes, reusable):"
  echo "https://$DOMAIN/post.php?pass=$PASS_B64&token=$TOKEN_5MIN"

  echo -e "\n${YELLOW}NOTE:${NC} Use one-time token once only, 15-minute token can be used multiple times within 15 mins."
}
#
send_whitelist_link_telegram() {
    read -p "Enter your API Bot token: " BOT_TOKEN
    read -p "Enter user's Telegram chat ID: " CHAT_ID

    # Remove newlines from TOKEN_OT (just in case)
    TOKEN_OT=$(echo "$TOKEN_OT" | tr -d '\n')

    WHITELIST_LINK="https://${DOMAIN}/post.php?pass=${PASS_B64}&token=${TOKEN_OT}"

    MESSAGE="Your  whitelist link (valid for a limited time):
${WHITELIST_LINK}"

    response=$(curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        -d chat_id="${CHAT_ID}" \
        --data-urlencode text="${MESSAGE}" \
        -d parse_mode="Markdown")

    echo "Telegram API response: $response"
    if echo "$response" | grep -q '"ok":true'; then
        echo "Whitelist link sent to Telegram user ${CHAT_ID}."
    else
        echo "Failed to send Telegram message."
    fi
}

# Check files and permissions
check_files_and_permissions() {
  log "Verifying files and permissions..."
  
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
      echo -e "${RED}[[X]] Missing file: $file${NC}"
      success=false
      continue
    fi

    # Check permissions
    actual_perm=$(stat -c "%a" "$file")
    if [[ "$actual_perm" != "$expected_perm" ]]; then
      echo -e "${RED}[[X]] Incorrect permissions on $file (Expected: $expected_perm, Got: $actual_perm)${NC}"
      success=false
    else
      echo -e "${GREEN}[[OK]] Permissions OK on $file ($expected_perm)${NC}"
    fi

    # Check ownership
    owner=$(stat -c "%U" "$file")
    group=$(stat -c "%G" "$file")
    if [[ "$owner" != "www-data" || "$group" != "www-data" ]]; then
      echo -e "${RED}[[X]] Incorrect ownership on $file (Expected: www-data:www-data, Got: $owner:$group)${NC}"
      success=false
    else
      echo -e "${GREEN}[[OK]] Ownership OK on $file (www-data:www-data)${NC}"
    fi
  done

  # Check directory
  if [[ ! -d "$WEB_DIR" ]]; then
    echo -e "${RED}[[X]] Missing web directory: $WEB_DIR${NC}"
    success=false
  else
    dir_perm=$(stat -c "%a" "$WEB_DIR")
    if [[ "$dir_perm" != "755" ]]; then
      echo -e "${RED}[[X]] Incorrect permissions on $WEB_DIR (Expected: 755, Got: $dir_perm)${NC}"
      success=false
    else
      echo -e "${GREEN}[[OK]] Web directory permissions OK ($dir_perm)${NC}"
    fi
  fi

  if [[ "$success" = true ]]; then
    log "${GREEN}All files verified successfully${NC}"
  else
    log "${YELLOW}Some files are missing or have incorrect permissions${NC}"
  fi
}

# Show system status
show_status() {
  echo -e "\n${BLUE}=== System Status ===${NC}"
  
  # Check NGINX
  if systemctl is-active nginx >/dev/null; then
    echo -e "NGINX: ${GREEN}RUNNING${NC}"
  else
    echo -e "NGINX: ${RED}STOPPED${NC}"
  fi
  
  # Check PHP-FPM
  if systemctl is-active "php$PHP_VERSION-fpm" >/dev/null; then
    echo -e "PHP-FPM: ${GREEN}RUNNING${NC}"
  else
    echo -e "PHP-FPM: ${RED}STOPPED${NC}"
  fi
  
  # Check whitelist count
  if [[ -f "$WHITE_LIST_FILE" ]]; then
    echo -e "Whitelisted IPs: ${BLUE}$(wc -l < "$WHITE_LIST_FILE")${NC}"
  else
    echo -e "Whitelist file: ${RED}MISSING${NC}"
  fi
  
  # Check domain
  if [[ -n "$DOMAIN" ]]; then
    echo -e "Configured domain: ${BLUE}$DOMAIN${NC}"
  else
    echo -e "Domain: ${YELLOW}NOT CONFIGURED${NC}"
  fi
  
  # Check ports
  if [[ -n "$PROXY_PORT" ]]; then
    echo -e "Proxy port: ${BLUE}$PROXY_PORT${NC}"
  else
    echo -e "Proxy port: ${YELLOW}NOT CONFIGURED${NC}"
  fi
  
  if [[ -n "$NGINX_PORT" ]]; then
    echo -e "Whitelist port: ${BLUE}$NGINX_PORT${NC}"
  else
    echo -e "Whitelist port: ${YELLOW}NOT CONFIGURED${NC}"
  fi
}

# Uninstall everything
uninstall() {
  echo -e "\n${RED}=== UNINSTALL ===${NC}"
  read -p "Are you sure you want to uninstall everything? [y/N] " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Uninstall cancelled."
    return
  fi
  
  log "Starting uninstallation..."
  
  # Stop services
  systemctl stop nginx || log "${YELLOW}Failed to stop NGINX${NC}"
  systemctl stop "php$PHP_VERSION-fpm" || log "${YELLOW}Failed to stop PHP-FPM${NC}"
  
  # Remove packages
  apt remove -y --purge nginx php-fpm php libnginx-mod-stream certbot python3-certbot-nginx || log "${YELLOW}Failed to remove some packages${NC}"
  
  # Remove configuration files
  rm -rf "$WEB_DIR/post.php" || log "${YELLOW}Failed to remove PHP script${NC}"
  rm -f "$WHITE_LIST_FILE" "$USED_TOKENS_FILE" "$PASSWORD_FILE" || log "${YELLOW}Failed to remove data files${NC}"
  rm -f "$WHITELIST_SITE_CONF" "$NGINX_SITES_LINK" || log "${YELLOW}Failed to remove NGINX config${NC}"
  rm -f "$STREAM_CONF_FILE" || log "${YELLOW}Failed to remove stream config${NC}"
  rm -f "$CONFIG_FILE" || log "${YELLOW}Failed to remove config file${NC}"
  
  # Clean up
  apt autoremove -y || log "${YELLOW}Failed to autoremove packages${NC}"
  
  log "${GREEN}Uninstallation complete.${NC}"
}

# Install everything
install_all() {
  check_root
  load_config
  create_backup
  
  log "Starting complete installation..."
  
  #install_mtproto_proxy
  install_nginx_with_stream
  install_php
  install_certbot
  create_files_and_permissions
  setup_nginx_site
  fix_permissions
  check_files_and_permissions
  setup_ufw_rules
  
  log "${GREEN}Installation completed successfully!${NC}"
  show_status
}

# ==============================================
# MAIN MENU
# ==============================================

show_menu() {
  while true; do
    clear
    echo -e "${BLUE}==== MTProto Proxy Whitelist Installer ====${NC}"
    echo -e "${GREEN}1) Install MTProto Proxy only"
    echo -e "2) Install everything (NGINX, PHP, whitelist system)"
    echo -e "3) Generate access URL with tokens"
    echo -e "4) Fix permissions"
    echo -e "5) Change Whitelist Password"
    echo -e "6) Check system status"
    echo -e "7) Uninstall everything full wipe "
    echo -e "${GREEN}8) Send whitelist link via Telegram${NC}"
    echo -e "0) Exit${NC}"
    echo -e "==========================================="
    
    read -p "Choose an option: " choice
    case $choice in
      1)
        check_root
        install_mtproto_proxy
        ;;
      2)
        install_all
        ;;
      3)
        check_root
        generate_token_url
        ;;
      4)
        check_root
        fix_permissions
        ;;
      5)
        check_root
        create_password
        ;;
      6)
        check_root
        show_status
        ;;
      7)
        check_root
        uninstall
        ;;

      8)
        check_root
        generate_token_url   # This should set $WHITELIST_LINK
        send_whitelist_link_telegram
        ;;

      0)
        echo -e "${BLUE}Exiting...${NC}"
        exit 0
        ;;
      *)
        echo -e "${RED}Invalid option. Please try again.${NC}"
        ;;
    esac
    
    read -p "Press Enter to continue..."
  done
}

# ==============================================
# SCRIPT ENTRY POINT
# ==============================================

# Initialize logging
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

# Check dependencies
check_dependencies

# Load any existing config
load_config

# Get PHP version
get_php_version

# Start main menu
show_menu
