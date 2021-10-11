import rsa

(pubkey, privkey) = rsa.newkeys(2048)

with open("key.pub", "wb") as f:
    f.write(pubkey.save_pkcs1())

with open("key.pri", "wb") as f:
    f.write(privkey.save_pkcs1())