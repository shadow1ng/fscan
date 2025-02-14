docker build -t redis-server .
docker run -d \
  -p 6379:6379 \
  --name redis-container \
  redis-server