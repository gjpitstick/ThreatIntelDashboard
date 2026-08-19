#!/usr/bin/env bash
# CTI Dashboard installer for a Debian/Ubuntu LXC container.
#
# Run this AS ROOT from inside the extracted project directory, e.g.:
#   cd cti-dashboard
#   sudo bash install.sh
#
# What it does:
#   1. Installs system packages (python3, nginx, sqlite3)
#   2. Creates a dedicated 'ctidash' system user
#   3. Copies the app to /opt/ctidash and sets up a Python venv
#   4. Creates .env from .env.example (edit it afterwards for API keys)
#   5. Installs + enables a systemd service running uvicorn
#   6. Configures nginx as a reverse proxy on the port you choose (default 80)
#
# Safe to re-run: it updates the existing install in place.

set -euo pipefail

APP_NAME="ctidash"
APP_USER="ctidash"
INSTALL_DIR="/opt/ctidash"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
NGINX_SITE="/etc/nginx/sites-available/${APP_NAME}"
NGINX_SITE_ENABLED="/etc/nginx/sites-enabled/${APP_NAME}"
INTERNAL_PORT="8000"

# --- Must be root -----------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo bash install.sh" >&2
  exit 1
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Installing system packages (python3, venv, pip, nginx, sqlite3)..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nginx sqlite3 curl >/dev/null

echo "==> Creating system user '${APP_USER}' (if needed)..."
if ! id "${APP_USER}" &>/dev/null; then
  useradd --system --home "${INSTALL_DIR}" --shell /usr/sbin/nologin "${APP_USER}"
fi

echo "==> Copying application to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
rsync -a --exclude='.venv' --exclude='data' --exclude='.git' --exclude='.env' \
  "${SOURCE_DIR}/" "${INSTALL_DIR}/" 2>/dev/null || \
  cp -r "${SOURCE_DIR}/." "${INSTALL_DIR}/"

mkdir -p "${INSTALL_DIR}/data"

echo "==> Setting up .env..."
if [[ ! -f "${INSTALL_DIR}/.env" ]]; then
  cp "${INSTALL_DIR}/.env.example" "${INSTALL_DIR}/.env"
  echo "    Created ${INSTALL_DIR}/.env from the example -- edit it to add"
  echo "    NVD_API_KEY / ABUSECH_API_KEY if you have them (both optional)."
fi

echo "==> Creating Python virtual environment..."
python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/pip" install -q --upgrade pip
"${INSTALL_DIR}/.venv/bin/pip" install -q -r "${INSTALL_DIR}/requirements.txt"

chown -R "${APP_USER}:${APP_USER}" "${INSTALL_DIR}"

echo "==> Installing systemd service..."
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=CTI Dashboard (FastAPI/uvicorn)
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port ${INTERNAL_PORT}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}/data
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${APP_NAME}" >/dev/null
systemctl restart "${APP_NAME}"

echo "==> Configuring nginx reverse proxy..."
read -rp "Port to expose the dashboard on [80]: " EXPOSED_PORT
EXPOSED_PORT="${EXPOSED_PORT:-80}"

cat > "${NGINX_SITE}" <<EOF
server {
    listen ${EXPOSED_PORT};
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:${INTERNAL_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

ln -sf "${NGINX_SITE}" "${NGINX_SITE_ENABLED}"
# Remove the default site only if it's still the untouched Debian default,
# to avoid a port clash on 80 -- leave it alone otherwise.
if [[ "${EXPOSED_PORT}" == "80" && -f /etc/nginx/sites-enabled/default ]]; then
  rm -f /etc/nginx/sites-enabled/default
fi

nginx -t
systemctl reload nginx

CONTAINER_IP="$(hostname -I | awk '{print $1}')"

echo ""
echo "======================================================================"
echo " CTI Dashboard installed."
echo ""
echo " Service:   systemctl status ${APP_NAME}"
echo " Logs:      journalctl -u ${APP_NAME} -f"
echo " Config:    ${INSTALL_DIR}/.env  (edit, then: systemctl restart ${APP_NAME})"
echo ""
echo " Dashboard: http://${CONTAINER_IP}:${EXPOSED_PORT}"
echo "======================================================================"
echo ""
echo "First data refresh runs automatically in the background now and can"
echo "take a minute or two. IOCs stay empty until you set ABUSECH_API_KEY"
echo "in ${INSTALL_DIR}/.env (free key: https://auth.abuse.ch/)."
