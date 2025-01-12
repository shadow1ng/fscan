# 使用Memcached官方镜像
FROM memcached:latest

# 开放11211端口
EXPOSE 11211

# 设置启动参数
# -m 64: 分配64MB内存
# -c 1024: 最大同时连接数1024
# -v: 显示版本信息
CMD ["memcached", "-m", "64", "-c", "1024", "-v"]