# Use official Node.js LTS image
FROM node:20

# Set working directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy all project files
COPY . .

# Expose port (Back4App uses environment variable)
ENV PORT=3000
EXPOSE $PORT

# Start the app
CMD ["node", "index.js"]