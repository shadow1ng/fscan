FROM tomcat:9.0-jdk8

# 删除默认应用
RUN rm -rf /usr/local/tomcat/webapps/*

# 复制tomcat-users.xml配置文件
COPY tomcat-users.xml /usr/local/tomcat/conf/

# 允许远程访问manager
COPY context.xml /usr/local/tomcat/webapps.dist/manager/META-INF/
COPY context.xml /usr/local/tomcat/webapps.dist/host-manager/META-INF/

# 复制默认应用
RUN cp -r /usr/local/tomcat/webapps.dist/* /usr/local/tomcat/webapps/

EXPOSE 8080
CMD ["catalina.sh", "run"]