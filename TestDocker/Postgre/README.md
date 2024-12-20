docker build -t postgres-server .
docker run -d \
-p 5432:5432 \
--name postgres-container \
postgres-server