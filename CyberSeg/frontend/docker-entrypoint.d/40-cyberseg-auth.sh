#!/bin/sh
# Enables HTTP basic auth on the dashboard when credentials are configured.
set -eu

snippet=/etc/nginx/cyberseg-auth.conf
passwords=/etc/nginx/cyberseg.htpasswd

if [ -n "${CYBERSEG_DASHBOARD_USER:-}" ] && [ -n "${CYBERSEG_DASHBOARD_PASSWORD:-}" ]; then
  hash=$(printf '%s' "$CYBERSEG_DASHBOARD_PASSWORD" | openssl passwd -apr1 -stdin)
  printf '%s:%s\n' "$CYBERSEG_DASHBOARD_USER" "$hash" > "$passwords"
  chown root:nginx "$passwords"
  chmod 640 "$passwords"
  printf 'auth_basic "CyberSeg";\nauth_basic_user_file %s;\n' "$passwords" > "$snippet"
  echo "CyberSeg: autenticación básica activada para el dashboard."
else
  : > "$snippet"
  echo "CyberSeg: dashboard sin autenticación; publícalo solo en 127.0.0.1 o tras un proxy autenticado."
fi
