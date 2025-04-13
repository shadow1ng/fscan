# 使用Oracle官方容器镜像
FROM container-registry.oracle.com/database/express:21.3.0-xe

# 设置环境变量
ENV ORACLE_PWD=123456
ENV ORACLE_CHARACTERSET=AL32UTF8

# 开放1521端口
EXPOSE 1521 5500

# 健康检查
HEALTHCHECK --interval=30s --timeout=30s --start-period=5m --retries=3 \
  CMD nc -z localhost 1521 || exit 1