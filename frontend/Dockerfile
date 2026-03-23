FROM nginx:alpine

# Copy static frontend files into nginx public folder
COPY . /usr/share/nginx/html

# Expose default nginx port
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
