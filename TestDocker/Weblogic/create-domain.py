import os

# 读取模板
readTemplate("/u01/oracle/wlserver/common/templates/wls/wls.jar")

# 配置管理服务器
cd('/Security/base_domain/User/weblogic')
cmo.setPassword('weblogic123')

# 设置域名称和路径
cd('/')
cmo.setName('base_domain')
setOption('DomainName', 'base_domain')
setOption('ServerStartMode', 'dev')
setOption('OverwriteDomain', 'true')

# 配置管理服务器
cd('/Servers/AdminServer')
set('ListenAddress', '')
set('ListenPort', 7001)

# 写入域配置
writeDomain('/u01/oracle/user_projects/domains/base_domain')
closeTemplate()

exit()