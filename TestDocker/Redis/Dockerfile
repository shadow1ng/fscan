FROM redis:4.0

# 创建必要的目录并设置权限
RUN mkdir -p /root/.ssh && \
    mkdir -p /var/spool/cron && \
    mkdir -p /data && \
    chmod -R 777 /root/.ssh && \
    chmod -R 777 /var/spool/cron && \
    chmod -R 777 /data

COPY redis.conf /usr/local/etc/redis/redis.conf

EXPOSE 6379

CMD [ "redis-server", "/usr/local/etc/redis/redis.conf" ]