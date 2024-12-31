docker run -d -p 20:20 -p 21:21 -e FTP_USER=admin  -e FTP_PASS=123456  -e PASV_ADDRESS=127.0.0.1 --name ftp bogem/ftp
Mac上可能有问题