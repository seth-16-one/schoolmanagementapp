FROM node:20

WORKDIR /usr/src/app

# Use the backend package files explicitly so Docker never installs from the repo root package.json.
COPY package*.json ./

RUN npm install

# Copy only the backend app sources into the image.


ENV PORT=3000
EXPOSE 3000

CMD ["npm", "start"]
