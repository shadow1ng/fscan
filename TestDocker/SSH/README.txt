docker build -t ubuntu-ssh .
docker run -d -p 2222:22 ubuntu-ssh