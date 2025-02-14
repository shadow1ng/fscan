docker build -t ubuntu-ssh .
docker run -d -p 22:22 ubuntu-ssh