docker build -t vnc-server .
docker run -d -p 5901:5901 vnc-server