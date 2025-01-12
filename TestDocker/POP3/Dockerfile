FROM ubuntu:20.04

# 避免交互式提示
ENV DEBIAN_FRONTEND=noninteractive

# 安装必要的包
RUN apt-get update && apt-get install -y \
    dovecot-pop3d \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# 生成SSL证书
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/dovecot.pem \
    -out /etc/ssl/certs/dovecot.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# 配置Dovecot
RUN echo '\
protocols = pop3\n\
listen = *\n\
ssl = yes\n\
ssl_cert = </etc/ssl/certs/dovecot.pem\n\
ssl_key = </etc/ssl/private/dovecot.pem\n\
auth_mechanisms = plain login\n\
disable_plaintext_auth = no\n\
mail_location = mbox:~/mail:INBOX=/var/mail/%u\n\
\n\
passdb {\n\
  driver = passwd-file\n\
  args = scheme=PLAIN username_format=%u /etc/dovecot/passwd\n\
}\n\
\n\
userdb {\n\
  driver = passwd-file\n\
  args = username_format=%u /etc/dovecot/users\n\
}\n\
' > /etc/dovecot/dovecot.conf

# 创建密码文件
RUN echo '\
admin:{PLAIN}admin123\n\
test:{PLAIN}test123\n\
root:{PLAIN}root123\n\
' > /etc/dovecot/passwd

# 创建用户文件
RUN echo '\
admin:x:1000:1000::/home/admin:/bin/false\n\
test:x:1001:1001::/home/test:/bin/false\n\
root:x:1002:1002::/home/root:/bin/false\n\
' > /etc/dovecot/users

# 创建必要的目录和权限
RUN mkdir -p /home/admin /home/test /home/root && \
    chown 1000:1000 /home/admin && \
    chown 1001:1001 /home/test && \
    chown 1002:1002 /home/root

# 暴露端口
EXPOSE 110 995

# 启动Dovecot
CMD ["dovecot", "-F"]