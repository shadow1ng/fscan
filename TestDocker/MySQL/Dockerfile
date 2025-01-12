# 使用MySQL官方镜像
FROM mysql:latest

# 设置环境变量
ENV MYSQL_ROOT_PASSWORD=Password
ENV MYSQL_DATABASE=mydb

# 开放3306端口
EXPOSE 3306

# MySQL配置
# 允许远程访问
COPY my.cnf /etc/mysql/conf.d/my.cnf

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s \
  CMD mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -e "SELECT 1" || exit 1