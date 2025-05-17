<?php
$raw = file_get_contents("/etc/nginx/.password");
list($stored_hash, $salt) = explode(":", trim($raw));

$token = $_GET['token'] ?? '';
$pass = $_GET['pass'] ?? '';

if (hash('sha256', $pass . $salt) !== $stored_hash || empty($token)) {
    http_response_code(403);
    exit('Access denied');
}

$ip = $_SERVER['REMOTE_ADDR'];
$entry = "allow $ip;\n";

// Check if IP already exists to avoid duplicates
$whitelistFile = "/etc/nginx/whitelist.txt";
$existing = file_exists($whitelistFile) ? file($whitelistFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

if (!in_array(trim($entry), $existing)) {
    file_put_contents($whitelistFile, $entry, FILE_APPEND);
    echo "IP $ip added.";
} else {
    echo "IP $ip already in whitelist.";
}
?>
