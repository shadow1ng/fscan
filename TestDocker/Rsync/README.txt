docker build -t rsync-weak .
docker run -d --name rsync-test -p 873:873 rsync-weak