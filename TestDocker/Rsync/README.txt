docker pull cassandra:3.11

docker run -d --name cassandra-test \
  -e CASSANDRA_AUTHENTICATOR=AllowAllAuthenticator \
  -p 9042:9042 \
  -p 9160:9160 \
  cassandra:3.11

docker run -d --name cassandra-test \
  -e CASSANDRA_AUTHENTICATOR=PasswordAuthenticator \
  -e CASSANDRA_PASSWORD=123456 \
  -e CASSANDRA_USER=admin \
  -p 9042:9042 \
  -p 9160:9160 \
  cassandra:3.11