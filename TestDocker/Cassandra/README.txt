docker build -t cassandra-weak .
docker run -d --name cassandra-test -e CASSANDRA_AUTHENTICATOR=AllowAllAuthenticator -p 9042:9042 -p 9160:9160 cassandra:3.11