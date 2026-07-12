#!/usr/bin/env bash
# Provisions a MySQL/MariaDB database + application user for secscan.
# Prompts for the admin password and the new app-user password (hidden input) —
# never accepts either as a flag, to avoid shell-history/`ps` leakage.
set -euo pipefail

HOST=""
PORT=3306
DB_NAME=""
APP_USER=""
ADMIN_USER=""
USE_SSL=false

usage() {
    echo "Usage: $0 --host <host> [--port 3306] --db-name <name> --app-user <user> --admin-user <user> [--ssl]" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --db-name) DB_NAME="$2"; shift 2 ;;
        --app-user) APP_USER="$2"; shift 2 ;;
        --admin-user) ADMIN_USER="$2"; shift 2 ;;
        --ssl) USE_SSL=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

if [[ -z "$HOST" || -z "$DB_NAME" || -z "$APP_USER" || -z "$ADMIN_USER" ]]; then
    usage
fi

if [[ ! "$DB_NAME" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "Error: --db-name must contain only letters, digits, and underscores." >&2
    exit 1
fi
if [[ ! "$APP_USER" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "Error: --app-user must contain only letters, digits, and underscores." >&2
    exit 1
fi

if ! command -v mysql >/dev/null 2>&1; then
    echo "Error: the 'mysql' CLI client is not on PATH." >&2
    exit 1
fi

read -rs -p "Admin password for '$ADMIN_USER'@'$HOST': " ADMIN_PASSWORD
echo
read -rs -p "New password for app user '$APP_USER': " APP_PASSWORD
echo
read -rs -p "Confirm app user password: " APP_PASSWORD_CONFIRM
echo

if [[ "$APP_PASSWORD" != "$APP_PASSWORD_CONFIRM" ]]; then
    echo "Error: app user passwords did not match." >&2
    exit 1
fi

ESCAPED_APP_PASSWORD="${APP_PASSWORD//\\/\\\\}"
ESCAPED_APP_PASSWORD="${ESCAPED_APP_PASSWORD//\'/\\\'}"

MYSQL_PWD="$ADMIN_PASSWORD" mysql --host="$HOST" --port="$PORT" --user="$ADMIN_USER" <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS '$APP_USER'@'%' IDENTIFIED BY '$ESCAPED_APP_PASSWORD';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$APP_USER'@'%';
FLUSH PRIVILEGES;
SQL

echo
echo "Database '$DB_NAME' and user '$APP_USER' are ready. Export:"
echo
echo "  export SECSCAN_DB_URL=mysql://$HOST:$PORT/$DB_NAME"
echo "  export DB_USERNAME=$APP_USER"
echo "  export DB_PASSWORD=$APP_PASSWORD"
if [[ "$USE_SSL" == true ]]; then
    echo "  export DB_SSL=true"
fi
