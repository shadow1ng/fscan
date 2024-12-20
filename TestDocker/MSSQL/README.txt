docker build -t mssql-server .
docker run -d \
  -p 1433:1433 \
  --name mssql-container \
  mssql-server