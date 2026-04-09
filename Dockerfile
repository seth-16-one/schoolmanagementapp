FROM node:20

WORKDIR /usr/src/app

# Copy dependency manifests first for better layer caching.
COPY . .

RUN npm install

# Copy the backend app files into the image.


# Debug step for Render builds: verify index.js and package files are present.
RUN ls -la

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

CMD ["npm", "start"]
