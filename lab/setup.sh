#!/bin/bash
set -e

WP_URL="http://localhost:80"
ADMIN_USER="admin"
ADMIN_PASS="admin123"
ADMIN_EMAIL="admin@ghostpress.lab"

echo "[*] Waiting for WordPress to be ready..."
until curl -sf "$WP_URL/" > /dev/null 2>&1; do
    sleep 2
done

echo "[*] Installing WP-CLI..."
curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
mv wp-cli.phar /usr/local/bin/wp

cd /var/www/html

echo "[*] Installing WordPress..."
wp core install \
    --url="http://localhost:8888" \
    --title="Ghostpress Lab" \
    --admin_user="$ADMIN_USER" \
    --admin_password="$ADMIN_PASS" \
    --admin_email="$ADMIN_EMAIL" \
    --skip-email \
    --allow-root

echo "[*] Creating additional weak users..."
wp user create editor editor@ghostpress.lab --role=editor --user_pass=editor123 --allow-root
wp user create author author@ghostpress.lab --role=author --user_pass=password --allow-root
wp user create subscriber subscriber@ghostpress.lab --role=subscriber --user_pass=subscriber --allow-root

echo "[*] Creating sample posts with author attribution..."
wp post create --post_title="Welcome to Ghostpress Lab" --post_content="This is a test site for security scanning." --post_status=publish --post_author=1 --allow-root
wp post create --post_title="Editor Post" --post_content="Post by the editor." --post_status=publish --post_author=2 --allow-root
wp post create --post_title="Author Post" --post_content="Post by the author." --post_status=publish --post_author=3 --allow-root

echo "[*] Installing vulnerable plugins..."
# Contact Form 7 - old version with known issues
wp plugin install contact-form-7 --version=5.3.2 --activate --allow-root || true

# Akismet (comes bundled, activate it)
wp plugin activate akismet --allow-root || true

# Classic Editor
wp plugin install classic-editor --activate --allow-root || true

# WP File Manager - historically had critical vulns
wp plugin install wp-file-manager --version=6.8 --activate --allow-root || true

# Elementor - widely used, old version
wp plugin install elementor --version=3.5.0 --activate --allow-root || true

echo "[*] Installing themes..."
wp theme install twentytwenty --activate --allow-root || true
wp theme install twentynineteen --allow-root || true

echo "[*] Enabling debug log..."
cat >> /var/www/html/wp-config.php << 'WPCONFIG'

// Debug settings for lab
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);
WPCONFIG

echo "[*] Creating debug.log with sample content..."
mkdir -p /var/www/html/wp-content
cat > /var/www/html/wp-content/debug.log << 'DEBUGLOG'
[07-Aug-2026 10:00:00 UTC] PHP Notice: Undefined variable: user_login in /var/www/html/wp-login.php on line 45
[07-Aug-2026 10:01:00 UTC] PHP Warning: file_get_contents(): Filename cannot be empty in /var/www/html/wp-content/plugins/vulnerable-plugin/index.php on line 12
[07-Aug-2026 10:02:00 UTC] WordPress database error: Table 'wordpress.wp_options' doesn't exist
DEBUGLOG
chown www-data:www-data /var/www/html/wp-content/debug.log

echo "[*] Creating config backup files..."
cp /var/www/html/wp-config.php /var/www/html/wp-config.php.bak
cp /var/www/html/wp-config.php /var/www/html/wp-config.bak
cp /var/www/html/wp-config.php /var/www/html/wp-config.txt
chown www-data:www-data /var/www/html/wp-config.php.bak /var/www/html/wp-config.bak /var/www/html/wp-config.txt

echo "[*] Creating a fake database export..."
cat > /var/www/html/dump.sql << 'SQLDUMP'
-- MySQL dump from Ghostpress Lab
-- Server version: 5.7
CREATE TABLE wp_users (
  ID bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  user_login varchar(60) NOT NULL DEFAULT '',
  user_pass varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (ID)
);
INSERT INTO wp_users VALUES (1,'admin','$P$BfakeHashForLabPurposes');
SQLDUMP
chown www-data:www-data /var/www/html/dump.sql

echo "[*] Enabling directory listing on uploads..."
cat > /var/www/html/wp-content/uploads/.htaccess << 'HTACCESS'
Options +Indexes
HTACCESS
mkdir -p /var/www/html/wp-content/uploads/2026/08
echo "test" > /var/www/html/wp-content/uploads/2026/08/secret-document.txt
chown -R www-data:www-data /var/www/html/wp-content/uploads

echo "[*] Enabling XML-RPC (default on, but make sure)..."
# XML-RPC is enabled by default in WordPress

echo "[*] Enabling user registration..."
wp option update users_can_register 1 --allow-root

echo "[*] Creating robots.txt..."
cat > /var/www/html/robots.txt << 'ROBOTS'
User-agent: *
Disallow: /wp-admin/
Disallow: /wp-includes/
Disallow: /wp-content/plugins/
Disallow: /wp-content/uploads/private/
Disallow: /backup/
Disallow: /old/
Allow: /wp-admin/admin-ajax.php

Sitemap: http://localhost:8888/wp-sitemap.xml
ROBOTS
chown www-data:www-data /var/www/html/robots.txt

echo "[*] Exposing readme.html (default in WP, ensure it's there)..."
# readme.html is included by default in WordPress

echo "[*] Setup complete! Vulnerable WordPress lab is ready."
echo "[*] URL: http://localhost:8888"
echo "[*] Admin: $ADMIN_USER / $ADMIN_PASS"
echo "[*] Editor: editor / editor123"
echo "[*] Author: author / password"
echo "[*] Subscriber: subscriber / subscriber"
