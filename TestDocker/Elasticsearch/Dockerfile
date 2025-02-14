FROM docker.elastic.co/elasticsearch/elasticsearch:7.9.3

# 设置环境变量允许单节点运行
ENV discovery.type=single-node

# 允许任意IP访问
ENV network.host=0.0.0.0

# 设置弱密码
ENV ELASTIC_PASSWORD=elastic123

# 暴露端口
EXPOSE 9200 9300

# 设置默认用户名elastic和密码elastic123
RUN echo 'elastic:elastic123' > /usr/share/elasticsearch/config/users

# 关闭xpack安全功能，使其可以无认证访问
RUN echo 'xpack.security.enabled: false' >> /usr/share/elasticsearch/config/elasticsearch.yml