FROM ubuntu:20.04

# 安装rsync
RUN apt-get update && \
    apt-get install -y rsync

# 创建测试目录和用户
RUN mkdir -p /data/public && \
    mkdir -p /data/secure && \
    useradd -m testuser && \
    echo "testuser:123456" | chpasswd

# 配置文件
RUN echo 'pid file = /var/run/rsyncd.pid' > /etc/rsyncd.conf && \
    echo 'log file = /var/log/rsyncd.log' >> /etc/rsyncd.conf && \
    echo 'transfer logging = yes' >> /etc/rsyncd.conf && \
    echo 'use chroot = yes' >> /etc/rsyncd.conf && \
    echo '[public]' >> /etc/rsyncd.conf && \
    echo 'path = /data/public' >> /etc/rsyncd.conf && \
    echo 'comment = Public Share' >> /etc/rsyncd.conf && \
    echo 'read only = yes' >> /etc/rsyncd.conf && \
    echo 'auth users = *' >> /etc/rsyncd.conf && \
    echo 'secrets file = /etc/rsyncd.secrets' >> /etc/rsyncd.conf && \
    echo '[anonymous]' >> /etc/rsyncd.conf && \
    echo 'path = /data/public' >> /etc/rsyncd.conf && \
    echo 'comment = Anonymous Share' >> /etc/rsyncd.conf && \
    echo 'read only = yes' >> /etc/rsyncd.conf && \
    echo 'auth users = ' >> /etc/rsyncd.conf

# 创建密码文件
RUN echo 'testuser:123456' > /etc/rsyncd.secrets && \
    echo 'root:root123' >> /etc/rsyncd.secrets && \
    chmod 600 /etc/rsyncd.secrets

# 暴露Rsync默认端口
EXPOSE 873

# 启动rsync守护进程
CMD ["rsync", "--daemon", "--no-detach", "--config=/etc/rsyncd.conf"]