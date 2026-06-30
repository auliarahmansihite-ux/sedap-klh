FROM node:20-bullseye-slim

# Set working directory
WORKDIR /usr/src/app

# Install dependencies (hanya package.json dulu agar build cache optimal)
COPY package*.json ./
RUN npm install --omit=dev

# Copy semua file project
COPY . .

# Buat folder uploads dan logs, lalu set ownership ke user 'node'
RUN mkdir -p uploads logs && chown -R node:node /usr/src/app

# Gunakan user non-root untuk keamanan
USER node

# Expose port internal container
EXPOSE 3000

# Perintah untuk menjalankan aplikasi
CMD ["node", "server.js"]
