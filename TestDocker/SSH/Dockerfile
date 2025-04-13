# 使用Ubuntu最新版本作为基础镜像
FROM ubuntu:latest

# 安装必要的软件包
RUN apt-get update && apt-get install -y \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# 创建SSH所需的目录
RUN mkdir /var/run/sshd

# 允许root用户SSH登录并设置密码
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN echo 'root:Aa123456789' | chpasswd

# 开放22端口
EXPOSE 22

# 启动SSH服务
CMD ["/usr/sbin/sshd", "-D"]