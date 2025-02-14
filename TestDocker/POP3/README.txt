docker build -t pop3-test .
docker run -d --name pop3-server -p 110:110 -p 995:995 pop3-test