FROM node:20-alpine

WORKDIR /app

# The middleware is a file: dependency — copy it before install so npm can link it.
COPY packages/middleware /app/packages/middleware
COPY demo/package.json /app/demo/package.json

WORKDIR /app/demo
RUN npm install --omit=dev --no-audit --no-fund

COPY demo/ /app/demo/

# DEMO keypair generated AT BUILD TIME, inside the image. Never committed, never
# shipped from the host. Regenerated on every rebuild.
RUN node gen-keys.js

RUN apk add --no-cache curl

EXPOSE 3000
CMD ["node", "src/server.js"]
