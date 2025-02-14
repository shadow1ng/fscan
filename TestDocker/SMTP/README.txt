docker build -t smtp-weak .
docker run -d --name smtp-test -p 25:25 smtp-weak