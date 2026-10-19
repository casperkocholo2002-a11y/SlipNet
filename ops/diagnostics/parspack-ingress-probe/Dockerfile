FROM node:22-alpine
WORKDIR /app
COPY server.js /app/server.js
ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000
USER node
CMD ["node", "/app/server.js"]
