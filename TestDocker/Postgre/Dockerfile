# 使用PostgreSQL官方镜像
FROM postgres:latest

# 设置环境变量
ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=123456
ENV POSTGRES_DB=mydb

# 开放5432端口
EXPOSE 5432

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s \
  CMD pg_isready -U postgres || exit 1