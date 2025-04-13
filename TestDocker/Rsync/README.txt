docker build -t rsync-test .
docker run -d --name rsync-server -p 873:873 rsync-test