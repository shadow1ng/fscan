FROM osixia/openldap:1.5.0

# 环境变量设置
ENV LDAP_ORGANISATION="Example Inc"
ENV LDAP_DOMAIN="example.com"
ENV LDAP_BASE_DN="dc=example,dc=com"
# 设置一个弱密码
ENV LDAP_ADMIN_PASSWORD="Aa123456789"
# 允许匿名访问
ENV LDAP_READONLY_USER="true"
ENV LDAP_READONLY_USER_USERNAME="readonly"
ENV LDAP_READONLY_USER_PASSWORD="readonly"

# 暴露端口
EXPOSE 389 636

# 创建初始化脚本
COPY bootstrap.ldif /container/service/slapd/assets/config/bootstrap/ldif/custom/