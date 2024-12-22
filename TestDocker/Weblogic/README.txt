docker build -t weblogic-weak .
docker run -d --name weblogic-test -p 7001:7001 -p 7002:7002 weblogic-weak