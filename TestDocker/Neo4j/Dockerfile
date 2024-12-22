FROM neo4j:4.4

ENV NEO4J_AUTH=neo4j/123456
ENV NEO4J_dbms_security_procedures_unrestricted=apoc.*
ENV NEO4J_dbms_security_auth_enabled=true

EXPOSE 7474 7687

CMD ["neo4j"]