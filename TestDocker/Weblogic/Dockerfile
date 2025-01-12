FROM container-registry.oracle.com/middleware/weblogic:12.2.1.4-dev

# 环境变量
ENV DOMAIN_NAME="base_domain" \
    ADMIN_PORT="7001" \
    ADMIN_NAME="weblogic" \
    ADMIN_PASSWORD="weblogic123" \
    PRODUCTION_MODE="dev" \
    DOMAIN_HOME="/u01/oracle/user_projects/domains/base_domain"

USER oracle

# 创建域配置脚本
COPY --chown=oracle:oracle create-domain.py /u01/oracle/
COPY --chown=oracle:oracle start.sh /u01/oracle/
RUN chmod +x /u01/oracle/start.sh

EXPOSE 7001 7002

CMD ["/u01/oracle/start.sh"]