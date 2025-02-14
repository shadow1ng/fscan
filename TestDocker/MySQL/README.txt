docker build -t mysql-server .
docker run -d -p 3306:3306 --name mysql-container mysql-server