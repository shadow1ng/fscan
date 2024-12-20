# 使用Redis官方镜像
FROM redis:latest

# 替换默认配置文件
COPY redis.conf /usr/local/etc/redis/redis.conf

# 开放6379端口
EXPOSE 6379

# 启动Redis
CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]