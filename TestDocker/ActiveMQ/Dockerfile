FROM rmohr/activemq:5.15.9

# 复制配置文件
COPY users.properties /opt/activemq/conf/users.properties
COPY activemq.xml /opt/activemq/conf/activemq.xml

# 暴露端口
EXPOSE 61616 61613

# 设置启动命令
CMD ["/opt/activemq/bin/activemq", "console"]