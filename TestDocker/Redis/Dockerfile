FROM redis:5.0.1

# 创建测试目录并设置权限
RUN mkdir -p /root/.ssh && \
    mkdir -p /var/spool/cron && \
    mkdir -p /var/spool/cron/crontabs && \
    mkdir -p /var/www/html && \
    mkdir -p /etc/redis && \
    mkdir -p /tmp/test && \
    chmod -R 777 /root/.ssh && \
    chmod -R 777 /var/spool/cron && \
    chmod -R 777 /var/spool/cron/crontabs && \
    chmod -R 777 /var/www/html && \
    chmod -R 777 /etc/redis && \
    chmod -R 777 /tmp/test && \
    echo "测试目录已创建，可以写入" > /tmp/test/test.txt

# 配置Redis允许远程连接和任意文件写入
RUN echo "port 6379\n\
bind 0.0.0.0\n\
dir /data\n\
dbfilename dump.rdb\n\
protected-mode no\n\
daemonize no\n\
appendonly no\n\
requirepass \"\"\n\
" > /etc/redis/redis.conf

WORKDIR /data

EXPOSE 6379

# 启动Redis服务器
CMD ["redis-server", "/etc/redis/redis.conf"]