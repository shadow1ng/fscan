FROM busybox:latest

# 安装必要的包
RUN ["busybox", "telnetd", "--help"]

# 创建测试用户
RUN adduser -D -h /home/test test && \
    echo "test:123456" | chpasswd

# 创建弱密码管理员
RUN adduser -D -h /home/admin admin && \
    echo "admin:admin" | chpasswd

# 暴露 Telnet 端口
EXPOSE 23

# 启动 Telnet 服务
CMD ["busybox", "telnetd", "-F", "-l", "/bin/sh"]