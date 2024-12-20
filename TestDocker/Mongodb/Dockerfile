# 使用MongoDB官方镜像
FROM mongo:latest

# 设置环境变量
ENV MONGO_INITDB_ROOT_USERNAME=admin
ENV MONGO_INITDB_ROOT_PASSWORD=123456

# 开放27017端口
EXPOSE 27017

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s \
  CMD mongosh --eval 'db.runCommand("ping").ok' localhost:27017/test --quiet