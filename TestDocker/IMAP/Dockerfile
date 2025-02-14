FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# 安装 Dovecot 和工具
RUN apt-get update && \
    apt-get install -y dovecot-imapd dovecot-gssapi ssl-cert net-tools procps && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 创建邮件存储目录和邮箱
RUN mkdir -p /var/mail/vhosts/ && \
    chmod 777 /var/mail/vhosts/

# 创建用户和密码文件
RUN echo "test:{PLAIN}123456" > /etc/dovecot/passwd && \
    echo "admin:{PLAIN}admin123" >> /etc/dovecot/passwd && \
    echo "root:{PLAIN}root123" >> /etc/dovecot/passwd && \
    chown dovecot:dovecot /etc/dovecot/passwd && \
    chmod 600 /etc/dovecot/passwd

# 配置Dovecot
RUN echo ' \
protocols = imap \n\
listen = * \n\
ssl = yes \n\
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem \n\
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key \n\
mail_location = mbox:~/mail:INBOX=/var/mail/%u \n\
disable_plaintext_auth = no \n\
auth_mechanisms = plain login \n\
auth_debug = yes \n\
auth_debug_passwords = yes \n\
mail_debug = yes \n\
\n\
passdb { \n\
  driver = passwd-file \n\
  args = scheme=PLAIN /etc/dovecot/passwd \n\
} \n\
\n\
userdb { \n\
  driver = static \n\
  args = uid=vmail gid=vmail home=/var/mail/%u \n\
} \n\
\n\
service auth { \n\
  user = dovecot \n\
  unix_listener auth-userdb { \n\
    mode = 0600 \n\
    user = vmail \n\
  } \n\
} \n\
\n\
service imap-login { \n\
  inet_listener imap { \n\
    port = 143 \n\
  } \n\
  inet_listener imaps { \n\
    port = 993 \n\
    ssl = yes \n\
  } \n\
} \n\
' > /etc/dovecot/dovecot.conf

# 创建vmail用户并设置正确的权限
RUN groupadd -g 5000 vmail && \
    useradd -g vmail -u 5000 vmail && \
    chown -R vmail:vmail /var/mail && \
    chown -R dovecot:dovecot /etc/dovecot && \
    chmod -R 644 /etc/dovecot/dovecot.conf

EXPOSE 143 993

CMD ["dovecot", "-F"]