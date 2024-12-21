docker build -t ldap-weak .
docker run -d --name ldap-test -p 389:389 -p 636:636 ldap-weak