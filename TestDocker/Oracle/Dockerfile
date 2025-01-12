# 使用Oracle官方容器镜像
FROM container-registry.oracle.com/database/express:latest

# 设置环境变量
ENV ORACLE_PWD=123456
ENV ORACLE_SID=XE
ENV ORACLE_PDB=XEPDB1

# 开放1521端口
EXPOSE 1521

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s \
  CMD sqlplus -L sys/123456@//localhost:1521/XE as sysdba << EOF
  exit;
  EOF