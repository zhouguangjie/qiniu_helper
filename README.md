## 自动更新七牛CDN域名证书
需要安装python环境
使用acme.sh定期获取新证书，再使用本脚本检查七牛云上的证书并更新。acme.sh用法请参考：https://github.com/acmesh-official/acme.sh
### 使用方法
1.在七牛云添加相应的域名
2.新建一个配置文件，参考：https://github.com/zhouguangjie/qiniu_helper/blob/main/qiniu_helper/domain_cert.template.json
3.设置定期执行脚本
`python ./qiniu_helper/qiniu_helper.py --renew <配置文件路径>