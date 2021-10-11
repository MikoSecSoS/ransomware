# ransomware
python写的一个不完整的勒索病毒，
- [x] RSA公钥加密AES密钥
- [x] 永恒之蓝进行蠕虫传播
- [ ] 每个文件拥有单独的AES密钥

## 免责声明！！！
**本仓库仅供学习交流，请勿用于非法用途。**
**任何组织和个人不得公开传播或用于任何商业盈利用途，否则一切后果由该组织或个人承担。本人不承担任何法律及连带责任！**
**当您打开本仓库时，说明您已经同意并接受本页面的所有信息。**

#### python版本
**版本：python3**

#### 库安装
pip install -r requirements.txt

#### rsa密钥对生成
python gen_rsa_key.py

#### 加密
替换main.py的hack_rsa_public_key
python main.py en

#### 解密
使用生成的密钥文件解密文件
python main.py de <私钥文件>
