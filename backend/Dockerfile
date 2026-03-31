# Author: Fabian Mattes
# Date: 23.03.2026

FROM node:20

WORKDIR /app

# install dependencies from package.json
COPY package*.json ./
RUN npm install

COPY . .

CMD ["node", "index.js"]
