首先需要在Oracle Container Registry网站注册并接受许可协议：
https://container-registry.oracle.com

docker login container-registry.oracle.com

docker build -t oracle-db .

docker run -d \
  -p 1521:1521 \
  --name oracle-container \
  oracle-db