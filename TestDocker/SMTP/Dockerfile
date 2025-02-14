FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# 安装必要的软件
RUN apt-get update && apt-get install -y \
    postfix \
    sasl2-bin \
    libsasl2-modules \
    mailutils \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

# 配置Postfix
RUN postconf -e 'smtpd_sasl_auth_enable = yes' \
    && postconf -e 'smtpd_sasl_security_options = noanonymous' \
    && postconf -e 'smtpd_sasl_local_domain =' \
    && postconf -e 'broken_sasl_auth_clients = yes' \
    && postconf -e 'smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination' \
    && postconf -e 'inet_interfaces = all'

# 配置SASL
RUN mkdir -p /etc/postfix/sasl/
RUN echo "pwcheck_method: auxprop" > /etc/postfix/sasl/smtpd.conf \
    && echo "auxprop_plugin: sasldb" >> /etc/postfix/sasl/smtpd.conf \
    && echo "mech_list: PLAIN LOGIN" >> /etc/postfix/sasl/smtpd.conf

# 创建SASL用户（使用固定域名localhost）
RUN echo "123456" | saslpasswd2 -p -c -u localhost test
RUN echo "admin123" | saslpasswd2 -p -c -u localhost admin
RUN echo "root123" | saslpasswd2 -p -c -u localhost root

# 设置权限
RUN chown postfix:postfix /etc/sasldb2

# 创建日志目录和文件
RUN mkdir -p /var/log && \
    touch /var/log/mail.log && \
    chmod 644 /var/log/mail.log

# 开放端口
EXPOSE 25

# 创建启动脚本
RUN echo '#!/bin/bash' > /start.sh \
    && echo 'service rsyslog start' >> /start.sh \
    && echo 'service postfix start' >> /start.sh \
    && echo 'tail -f /var/log/mail.log' >> /start.sh \
    && chmod +x /start.sh

CMD ["/start.sh"]