#!/bin/bash
# ================================================
# deploy.sh — Script deployment otomatis SEDAP KLH
# Jalankan di VPS: bash deploy.sh
# ================================================
set -e  # Stop jika ada error

APP_DIR="/var/www/sedap-klh"
APP_NAME="sedap-klh"
BRANCH="master"

echo ""
echo "🌿 ==============================="
echo "   SEDAP KLH — Auto Deploy"
echo "=================================="

# 1. Masuk ke direktori aplikasi
cd "$APP_DIR"
echo "📁 Working dir: $(pwd)"

# 2. Backup database sebelum update
BACKUP_DIR="$APP_DIR/backups"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ -f "$APP_DIR/sedap-klh.db" ]; then
  cp "$APP_DIR/sedap-klh.db" "$BACKUP_DIR/sedap-klh_$TIMESTAMP.db"
  echo "💾 Database backup: backups/sedap-klh_$TIMESTAMP.db"
fi

# Hapus backup lebih dari 7 hari
find "$BACKUP_DIR" -name "*.db" -mtime +7 -delete 2>/dev/null && echo "🗑️  Backup lama (>7 hari) dihapus"

# 3. Pull perubahan terbaru dari Git
echo ""
echo "📥 Pulling from Git ($BRANCH)..."
git fetch origin
git reset --hard origin/$BRANCH
echo "✅ Code updated."

# 4. Install dependencies (hanya production)
echo ""
echo "📦 Installing dependencies..."
npm install --omit=dev --silent
echo "✅ Dependencies OK."

# 5. Restart aplikasi via PM2
echo ""
echo "🔄 Restarting PM2..."
if pm2 describe "$APP_NAME" > /dev/null 2>&1; then
  pm2 restart "$APP_NAME"
else
  pm2 start ecosystem.config.js
  pm2 save
fi

# 6. Tunggu sebentar lalu cek status
sleep 2
echo ""
echo "📊 Status PM2:"
pm2 status "$APP_NAME" --no-color

echo ""
echo "✅ ================================"
echo "   Deploy selesai!"
echo "=================================="
echo ""
