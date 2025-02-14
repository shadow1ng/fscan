docker build -t weak-imap .
docker run -d --name imap-test -p 143:143 -p 993:993 weak-imap