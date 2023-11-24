import base64
import hashlib
import math
import random
import rsa
from Crypto.Cipher import AES





class Encrypt:
    def __init__(self, key, iv):
        self.key = key.encode('utf-8')
        self.iv = iv.encode('utf-8')


    # @staticmethod
    def pkcs7padding(self, text):
        """
        明文使用PKCS7填充
        """

        bs = 16
        length = len(text)
        bytes_length = len(text.encode('utf-8'))
        padding_size = length if (bytes_length == length) else bytes_length
        padding = bs - padding_size % bs
        padding_text = chr(padding) * padding
        self.coding = chr(padding)
        return text + padding_text

    def aes_encrypt(self, content):
        """
        AES加密
        """


        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        # 处理明文
        content_padding = self.pkcs7padding(content)
        # 加密
        encrypt_bytes = cipher.encrypt(content_padding.encode('utf-8'))
        # 重新编码
        result = str(base64.b64encode(encrypt_bytes), encoding='utf-8')
        return result

    def aes_decrypt(self, content):
        """
        AES解密
        """
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        content = base64.b64decode(content)
        text = cipher.decrypt(content).decode('utf-8')
        return text.rstrip(self.coding)

    def rsa_encrypt(self,content,pemfile):
        public_key = get_rsa_key(pemfile,content)
        crypto = rsa.encrypt(content, public_key)
        rsaEncryptData= base64.b64encode(crypto).decode('utf-8')
        return rsaEncryptData
        # params = {
        #     'secretKeyDecode': getSessionStorageItem('rsaEncryptData') | | rsaEncrypt(),
        # }


def get_rsa_key(pemfile,data):

    with open(pemfile) as f:
        data = f.read()
        key = rsa.PublicKey.load_pkcs1_openssl_pem(data)
        return key

def generatekey(num):
    library = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    key = ''
    for i in range(num):
        randomPoz = math.floor(random.random() * len(library))
        key += library[randomPoz:randomPoz + 1]
    print(key)
    return key
    random_generator = Random.new().read
    rsa = RSA.generate(2048, random_generator)
    # 生成私钥
    private_key = rsa.exportKey()
    print(private_key.decode('utf-8'))


def lagou_positionAjax(data):
    '''
        request['headers']['X-S-Header']
        postdata
    :param data:
    :return:
    '''
    secret = Encrypt(aesKey,aes_iv)
    res = secret.aes_encrypt(data)

def lagou_agreement(data):
    '''
    request['headers']['X-K-Header']
    :param data:
    :return:
    '''


if __name__ == '__main__':
    pemfile='rsa_pubkey.pem'
    aesKey  = generatekey(32)
    aesKey='h4CMPblKQYGUE67=QqqgaCYtECSd/5Qz'
    aes_iv = 'c558Gq0YQK2QUlMc'  # 需要16位
    data = "{first: 'true', needAddtionalResult: 'false', city: '上海', pn: '3', kd: 'PHP'}"
    aesKey = 'b6fd9ad9c9f8fe8e31adb617adb4faed'  # 32字节密钥
    aes_iv = '31dfb079af3127c7'  # 16字节IV
    data='fea725d2e8a765c8a508ef6e19aa26a1'
    secret = Encrypt(aesKey,aes_iv)
    res = secret.aes_encrypt(data)
    print(res)
    # data = '{"originHeader":"{\"deviceType\":1}","code":"1AEE3EA6CDAEE8D1CDB584D48229CAA482237B50BEEEA2F22BBF56B5AE3EA978"}'
    # secret = Encrypt(aesKey,aes_iv)
    # res = secret.aes_encrypt(data)
    # print(res)
    #
    # res = secret.rsa_encrypt(aesKey.encode(),pemfile)
    # print(res)