docker build -t rabbitmq-weak .
docker run -d --name rabbitmq-test -p 5672:5672 -p 15672:15672 rabbitmq-weak