docker build -t activemq-weak .
docker run -d --name activemq-test -p 61616:61616 -p 8161:8161 -p 61613:61613 activemq-weak