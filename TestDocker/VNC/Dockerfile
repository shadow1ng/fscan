FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

# 安装必要的包
RUN apt-get update && apt-get install -y \
    tightvncserver \
    xfce4 \
    xfce4-terminal \
    supervisor

# 创建新用户
RUN useradd -m vncuser
ENV USER=vncuser
ENV HOME=/home/vncuser

# 设置supervisor配置
RUN mkdir -p /var/log/supervisor
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# 切换到vncuser用户
USER vncuser
WORKDIR /home/vncuser

# 创建必要的文件和目录
RUN touch ~/.Xauthority
RUN mkdir -p ~/.vnc

# 创建启动脚本
RUN echo '#!/bin/bash\nxrdb $HOME/.Xresources\nstartxfce4 &' > ~/.vnc/xstartup
RUN chmod +x ~/.vnc/xstartup

# 设置VNC密码
RUN echo "123456" | vncpasswd -f > ~/.vnc/passwd
RUN chmod 600 ~/.vnc/passwd

# 切回root用户来运行supervisor
USER root

# 暴露VNC端口
EXPOSE 5901

# 使用supervisor启动服务
CMD ["/usr/bin/supervisord"]