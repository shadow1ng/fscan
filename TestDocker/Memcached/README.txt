docker build -t memcached-server .
docker run -d \
  -p 11211:11211 \
  --name memcached-container \
  memcached-server