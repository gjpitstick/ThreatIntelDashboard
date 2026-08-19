#!/usr/bin/env bash
# CTI Dashboard installer for a Debian/Ubuntu LXC container.
#
# Two ways to run it:
#
#   1) From a git repo (recommended -- makes /opt/ctidash the live checkout,
#      so future updates are just `git pull && systemctl restart ctidash`):
#        sudo bash install.sh https://github.com/you/cti-dashboard.git
#      For a private repo over SSH, make sure the container can already
#      authenticate (deploy key / SSH agent) before running this, e.g.:
#        sudo bash install.sh git@github.com:you/cti-dashboard.git
#
#   2) From a local extracted copy (no git):
#        cd cti-dashboard
#        sudo bash install.sh
#
# What it does either way:
#   1. Installs system packages (python3, git, nginx, sqlite3)
#   2. Creates a dedicated 'ctidash' system user
#   3. Gets the app into /opt/ctidash (clone or copy) and sets up a venv
#   4. Creates .env if it doesn't exist yet (edit it afterwards for API keys)
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
REPO_URL="${1:-}"

# --- Must be root -----------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo bash install.sh [git-repo-url]" >&2
  exit 1
fi

echo "==> Installing system packages (python3, venv, pip, git, nginx, sqlite3)..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git nginx sqlite3 curl rsync >/dev/null

echo "==> Creating system user '${APP_USER}' (if needed)..."
if ! id "${APP_USER}" &>/dev/null; then
  useradd --system --home "${INSTALL_DIR}" --shell /usr/sbin/nologin "${APP_USER}"
fi

if [[ -n "${REPO_URL}" ]]; then
  # --- Mode 1: git clone/pull directly into INSTALL_DIR ---------------
  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    echo "==> Existing git checkout found at ${INSTALL_DIR} -- pulling latest..."
    git config --global --add safe.directory "${INSTALL_DIR}" || true
    git -C "${INSTALL_DIR}" pull --ff-only
  elif [[ -d "${INSTALL_DIR}" && -n "$(ls -A "${INSTALL_DIR}" 2>/dev/null)" ]]; then
    echo "ERROR: ${INSTALL_DIR} already exists and isn't a git checkout." >&2
    echo "Back it up / remove it first, or re-run without a repo URL to" >&2
    echo "update it as a plain local copy instead." >&2
    exit 1
  else
    echo "==> Cloning ${REPO_URL} into ${INSTALL_DIR}..."
    git clone "${REPO_URL}" "${INSTALL_DIR}"
    git config --global --add safe.directory "${INSTALL_DIR}" || true
  fi
else
  # --- Mode 2: copy from wherever this script is running from ---------
  SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ "${SOURCE_DIR}" == "${INSTALL_DIR}" ]]; then
    echo "==> Already running from ${INSTALL_DIR}, nothing to copy."
  else
    echo "==> Copying application from ${SOURCE_DIR} to ${INSTALL_DIR}..."
    mkdir -p "${INSTALL_DIR}"
    if command -v rsync &>/dev/null; then
      rsync -a --exclude='.venv' --exclude='data' --exclude='.git' --exclude='.env' \
        "${SOURCE_DIR}/" "${INSTALL_DIR}/"
    else
      cp -r "${SOURCE_DIR}/." "${INSTALL_DIR}/"
      rm -rf "${INSTALL_DIR}/.venv" "${INSTALL_DIR}/data" "${INSTALL_DIR}/.git" "${INSTALL_DIR}/.env"
    fi
  fi
fi

mkdir -p "${INSTALL_DIR}/data"

echo "==> Setting up .env..."
if [[ ! -f "${INSTALL_DIR}/.env" ]]; then
  if [[ -f "${INSTALL_DIR}/.env.example" ]]; then
    cp "${INSTALL_DIR}/.env.example" "${INSTALL_DIR}/.env"
  else
    # .env.example is a dotfile -- easy to lose in a manual GitHub upload
    # (Finder/Explorer hide dotfiles by default) or a stripped-down clone.
    # Fall back to writing sane defaults directly so install never hard-fails.
    echo "    .env.example not found in the checkout -- writing defaults directly."
    cat > "${INSTALL_DIR}/.env" <<'ENVEOF'
NVD_API_KEY=
ABUSECH_API_KEY=
APP_PORT=8000
REFRESH_INTERVAL_HOURS=4
LOOKBACK_DAYS=7
DATABASE_PATH=./data/ctidash.db
LOG_LEVEL=INFO
ENVEOF
  fi
  echo "    Created ${INSTALL_DIR}/.env -- edit it to add NVD_API_KEY /"
  echo "    ABUSECH_API_KEY if you have them (both optional)."
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
NGINX_ALREADY_CONFIGURED="false"
[[ -f "${NGINX_SITE}" ]] && NGINX_ALREADY_CONFIGURED="true"

if [[ "${NGINX_ALREADY_CONFIGURED}" == "true" ]]; then
  echo "    nginx site already configured at ${NGINX_SITE}, leaving it as-is."
else
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
fi

nginx -t
systemctl reload nginx

CONTAINER_IP="$(hostname -I | awk '{print $1}')"
EXPOSED_PORT="${EXPOSED_PORT:-$(grep -oP 'listen \K[0-9]+' "${NGINX_SITE}" 2>/dev/null || echo 80)}"

echo ""
echo "======================================================================"
echo " CTI Dashboard installed at ${INSTALL_DIR}."
echo ""
echo " Service:   systemctl status ${APP_NAME}"
echo " Logs:      journalctl -u ${APP_NAME} -f"
echo " Config:    ${INSTALL_DIR}/.env  (edit, then: systemctl restart ${APP_NAME})"
if [[ -d "${INSTALL_DIR}/.git" ]]; then
echo " Update:    cd ${INSTALL_DIR} && git pull && systemctl restart ${APP_NAME}"
echo "            (or just re-run: sudo bash install.sh ${REPO_URL})"
fi
echo ""
echo " Dashboard: http://${CONTAINER_IP}:${EXPOSED_PORT}"
echo "======================================================================"
echo ""
echo "First data refresh runs automatically in the background now and can"
echo "take a minute or two. IOCs stay empty until you set ABUSECH_API_KEY"
echo "in ${INSTALL_DIR}/.env (free key: https://auth.abuse.ch/)."
