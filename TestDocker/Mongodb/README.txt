docker build -t mongodb-server .
docker run -d \
  -p 27017:27017 \
  --name mongodb-container \
  mongodb-server