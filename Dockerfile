# ---------------------------------------
# STAGE 1: Frontend Bouwen
# ---------------------------------------
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

# Update npm direct om CVE's in de build-tooling op te lossen
RUN npm install -g npm@latest

# Kopieer package files en installeer dependencies
COPY frontend/package*.json ./
RUN npm install

# Kopieer broncode en bouw de productie versie
COPY frontend/ .
RUN npm run build

# ---------------------------------------
# STAGE 2: Backend Bouwen
# ---------------------------------------
FROM node:20-alpine AS backend-builder
WORKDIR /app/backend

# Update npm ook hier voor de zekerheid
RUN npm install -g npm@latest

# Kopieer package files en installeer dependencies
COPY backend/package*.json ./
RUN npm install

# Kopieer broncode en bouw TypeScript naar JavaScript
COPY backend/ .
RUN npm run build

# ---------------------------------------
# STAGE 3: Final Production Image
# ---------------------------------------
FROM node:20-alpine
WORKDIR /app/backend

RUN apk add --no-cache tzdata

# Update npm in de final image zodat 'npm install' veilig gebeurt
RUN npm install -g npm@latest

# Installeer productie dependencies
COPY backend/package*.json ./
RUN npm install --only=production

# Kopieer de gebouwde code
COPY --from=backend-builder /app/backend/dist ./dist
COPY --from=frontend-builder /app/frontend/dist ../frontend/dist

# Maak de upload map aan EN zet rechten goed
RUN mkdir -p uploads && chown -R node:node /app

# Environment variabelen
ENV TZ=UTC
ENV APP_LOCALE=en-GB
ENV PORT=3000
ENV NODE_ENV=production

# Schakel over naar de veilige 'node' gebruiker
USER node

# Exposeer de poort
EXPOSE 3000

# Start de app
CMD ["node", "dist/index.js"]