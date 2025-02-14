# 使用SQL Server官方镜像
FROM mcr.microsoft.com/mssql/server:2022-latest

# 设置环境变量
ENV ACCEPT_EULA=Y
ENV MSSQL_SA_PASSWORD=P@ssword123
ENV MSSQL_PID=Express

# 开放1433端口
EXPOSE 1433

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s \
  CMD /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P P@ssword123 -Q "SELECT 1" || exit 1