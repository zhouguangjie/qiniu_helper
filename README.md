## 自动更新七牛CDN域名证书
需要安装python环境

使用acme.sh定期获取新证书，再使用本脚本检查七牛云上的证书并更新。acme.sh用法参考：[acme.sh](https://github.com/acmesh-official/acme.sh)

### 设置脚本需要的环境变量
调用脚本前都要设置七牛API的accesskey和secretkey环境变量
`export QINIU_ACCESSKEY=<accesskey>`  

`export QINIU_SECRETKEY=<secretkey>`

### 定期更新域名证书
1. 在七牛云添加相应的域名

2. 新建一个配置文件，参考[模板](https://github.com/zhouguangjie/qiniu_helper/blob/main/src/domain_cert.template.json)

3. 设置定期执行脚本
    `python ./src/qiniu_helper.py --renew <配置文件路径>`

### 定期移除本脚本上传过的到期证书
1. 设置定期执行脚本

    `python ./src/qiniu_helper.py --rm_expired`