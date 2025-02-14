docker build -t tomcat-weak .
docker run -d --name tomcat-test -p 8080:8080 tomcat-weak