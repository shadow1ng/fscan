FROM ubuntu:20.04

# 安装SNMP服务
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y snmpd && \
    rm -rf /var/lib/apt/lists/*

# 备份原配置
RUN cp /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.orig

# 创建新的配置文件
RUN echo "rocommunity public default" > /etc/snmp/snmpd.conf && \
    echo "rocommunity private default" >> /etc/snmp/snmpd.conf && \
    echo "rocommunity cisco default" >> /etc/snmp/snmpd.conf && \
    echo "rocommunity community default" >> /etc/snmp/snmpd.conf && \
    # 允许从任何地址访问
    echo "agentAddress udp:161,udp6:[::1]:161" >> /etc/snmp/snmpd.conf

# 开放SNMP端口
EXPOSE 161/udp

# 启动SNMP服务
CMD ["snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmp/snmpd.conf"]