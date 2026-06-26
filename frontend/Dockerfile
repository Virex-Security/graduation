FROM node:18-alpine

WORKDIR /app

# Copy package descriptors first to leverage Docker build cache
COPY package.json package-lock.json ./

# Install npm packages
RUN npm ci

# Copy frontend source files
COPY . .

# Expose Vite Dev Server Port
EXPOSE 8070

# Run Vite dev server, binding to all interfaces on port 8070
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "8070"]
