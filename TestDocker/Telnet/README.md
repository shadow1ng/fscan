docker build -t telnet-test .
docker run -d -p 23:23 --name telnet-server telnet-test