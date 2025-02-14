docker build -t snmp-weak .
docker run -d --name snmp-test -p 161:161/udp snmp-weak