#!/bin/sh
# HTTPS without a domain: a local certificate authority (CA) and a certificate
# for the server's IP. Each device installs the CA once from
# http://<IP>/certificado and then trusts https://<IP>/ like any website.
set -eu

tls=/etc/cyberseg/tls
public=/etc/cyberseg/public
mkdir -p "$tls" "$public"
chmod 700 "$tls"

# 127.0.0.1 plus the server's IPv4 addresses (CYBERSEG_SERVER_IP, comma separated).
ips="127.0.0.1"
for ip in $(printf '%s' "${CYBERSEG_SERVER_IP:-}" | tr ',' ' '); do
  case "$ip" in
    *[!0-9.]*|"") echo "CyberSeg: se ignora CYBERSEG_SERVER_IP='$ip' (solo IPv4)." ;;
    127.0.0.1) ;;
    *) ips="$ips $ip" ;;
  esac
done
# The first configured address (the LAN IP) names the certificate and pages.
main_ip=$(printf '%s' "$ips" | awk '{print ($2 != "") ? $2 : $1}')
san="DNS:localhost"
constraints="permitted;DNS:localhost"
for ip in $ips; do
  san="$san,IP:$ip"
  constraints="$constraints,permitted;IP:$ip/255.255.255.255"
done

# The CA may only certify these IPs (name constraints): even if its key were
# stolen it could not impersonate any other website.
if [ ! -s "$tls/ca.key" ] || [ "$(cat "$tls/ca.ips" 2>/dev/null)" != "$ips" ]; then
  if [ -s "$tls/ca.key" ]; then
    echo "CyberSeg: las IPs del servidor cambiaron; se crea una CA nueva. Vuelve a instalarla en tus equipos."
  fi
  openssl ecparam -name prime256v1 -genkey -noout -out "$tls/ca.key"
  openssl req -x509 -new -key "$tls/ca.key" -sha256 -days 3650 \
    -subj "/O=CyberSeg/CN=CyberSeg CA local $main_ip" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "nameConstraints=critical,$constraints" \
    -out "$tls/ca.crt" 2>/dev/null
  printf '%s' "$ips" > "$tls/ca.ips"
  rm -f "$tls/server.crt" "$tls/index.txt" "$tls/crlnumber"
fi

# Revocation list published over plain HTTP: Windows (Schannel) refuses
# certificates whose revocation status it cannot check.
http_port="${CYBERSEG_HTTP_PORT:-80}"
http_suffix=""
[ "$http_port" = "80" ] || http_suffix=":$http_port"
# One URL per address: LAN and VPN clients each reach the one on their route.
crl_urls=""
for ip in $ips; do
  [ "$ip" = "127.0.0.1" ] && [ "$ips" != "127.0.0.1" ] && continue
  crl_urls="${crl_urls:+$crl_urls,}URI:http://$ip$http_suffix/cyberseg.crl"
done
extensions=$(printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\ncrlDistributionPoints=%s\n' "$san" "$crl_urls")

# Server certificate: renewed 30 days before it expires or when its names change.
if [ ! -s "$tls/server.crt" ] || [ "$(cat "$tls/server.ext" 2>/dev/null)" != "$extensions" ] \
  || ! openssl x509 -checkend 2592000 -noout -in "$tls/server.crt" >/dev/null 2>&1; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$tls/server.key"
  openssl req -new -key "$tls/server.key" -subj "/O=CyberSeg/CN=$main_ip" -out "$tls/server.csr" 2>/dev/null
  printf '%s\n' "$extensions" > "$tls/server.ext"
  openssl x509 -req -in "$tls/server.csr" -CA "$tls/ca.crt" -CAkey "$tls/ca.key" -CAcreateserial \
    -days 825 -sha256 -extfile "$tls/server.ext" -out "$tls/server.crt" 2>/dev/null
  rm -f "$tls/server.csr"
fi
chmod 600 "$tls"/*.key

[ -f "$tls/index.txt" ] || : > "$tls/index.txt"
[ -f "$tls/crlnumber" ] || echo 1000 > "$tls/crlnumber"
cat > "$tls/ca.cnf" <<EOF
[ ca ]
default_ca = local
[ local ]
database = $tls/index.txt
crlnumber = $tls/crlnumber
default_md = sha256
default_crl_days = 3650
EOF
openssl ca -gencrl -config "$tls/ca.cnf" -keyfile "$tls/ca.key" -cert "$tls/ca.crt" -out "$public/cyberseg.crl.pem" 2>/dev/null
openssl crl -in "$public/cyberseg.crl.pem" -outform DER -out "$public/cyberseg.crl"
rm -f "$public/cyberseg.crl.pem"

cp "$tls/ca.crt" "$public/cyberseg-ca.crt"
fingerprint=$(openssl x509 -noout -fingerprint -sha256 -in "$tls/ca.crt" | cut -d= -f2)
printf '%s\n' "$fingerprint" > "$public/fingerprint.txt"

port="${CYBERSEG_HTTPS_PORT:-443}"
suffix=""
[ "$port" = "443" ] || suffix=":$port"
# shellcheck disable=SC2016 # $host and $request_uri are nginx variables
printf 'return 301 https://$host%s$request_uri;\n' "$suffix" > /etc/nginx/cyberseg-redirect.conf

cat > "$public/certificado.html" <<EOF
<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberSeg · Certificado</title><style>
body{font-family:system-ui,Segoe UI,sans-serif;background:#06101e;color:#dcecff;margin:0;padding:24px;line-height:1.55}
main{max-width:760px;margin:auto}a{color:#51cfff}code{background:#0f2440;padding:2px 6px;border-radius:4px;word-break:break-all}
.button{display:inline-block;background:#51cfff;color:#06101e;font-weight:700;padding:12px 18px;border-radius:8px;text-decoration:none;margin:8px 0}
section{background:#091a2d;border:1px solid #1d4369;border-radius:12px;padding:16px 20px;margin:16px 0}h2{font-size:17px;margin:0 0 6px}
</style></head><body><main>
<h1>Conectar con CyberSeg</h1>
<p>Este servidor no tiene dominio, así que usa su propio certificado. Instálalo <b>una vez</b> en cada equipo y después entra en
<a href="https://$main_ip$suffix/">https://$main_ip$suffix/</a> sin advertencias.</p>
<a class="button" href="/cyberseg-ca.crt" download>Descargar certificado (cyberseg-ca.crt)</a>
<p>Antes de instalarlo, comprueba que su huella SHA-256 coincide con la que mostró el servidor al instalarse:<br><code>$fingerprint</code></p>
<section><h2>Windows</h2>Usa el programa <b>CyberSeg.exe</b> (lo instala por ti), o abre el archivo → <i>Instalar certificado</i> →
<i>Usuario actual</i> → <i>Colocar todos los certificados en el siguiente almacén</i> → <i>Entidades de certificación raíz de confianza</i> → Finalizar.</section>
<section><h2>Android</h2>Ajustes → Seguridad → Más ajustes de seguridad → Cifrado y credenciales → Instalar un certificado → <i>Certificado de CA</i>.</section>
<section><h2>iPhone / iPad</h2>Abre el archivo y acepta descargar el perfil → Ajustes → Perfil descargado → Instalar.
Después: Ajustes → General → Información → Ajustes de confianza de certificados → activa <i>CyberSeg CA local</i>.</section>
<section><h2>Linux / Firefox</h2><code>sudo cp cyberseg-ca.crt /usr/local/share/ca-certificates/ &amp;&amp; sudo update-ca-certificates</code><br>
Firefox: Ajustes → Privacidad y seguridad → Ver certificados → Autoridades → Importar.</section>
<p>Este certificado solo puede validar las direcciones de este servidor ($ips); no sirve para ningún otro sitio web.</p>
</main></body></html>
EOF
echo "CyberSeg: HTTPS listo en https://$main_ip$suffix/ · huella SHA-256 de la CA: $fingerprint"
