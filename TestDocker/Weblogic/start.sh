#!/bin/bash

# 创建域
wlst.sh -skipWLSModuleScanning /u01/oracle/create-domain.py

# 等待域创建完成
sleep 5

# 启动服务器
/u01/oracle/user_projects/domains/base_domain/bin/startWebLogic.sh