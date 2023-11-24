const crypto = require('crypto');
const CryptoJS = require('crypto-js');
const { resourceUsage } = require('process');

// 加密函数
function encrypt(text, key, iv) {
    // 将十六进制字符串转换为 Buffer
    key = Buffer.from(key, 'hex');
    iv = Buffer.from(iv, 'hex');

    let cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf-8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

// 解密函数
function decrypt(encryptedText, key, iv) {
    // 将十六进制字符串转换为 Buffer
    key = Buffer.from(key, 'hex');
    iv = Buffer.from(iv, 'hex');

    let decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedText, 'base64', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}


function get_Buffer(base64String){
    var byteArray = Array.from(atob(base64String), (c) => c.charCodeAt(0));
    var words = [];
    for (var i = 0; i < byteArray.length; i += 4) {
        var word =
            (byteArray[i] << 24) |
            (byteArray[i + 1] << 16) |
            (byteArray[i + 2] << 8) |
            byteArray[i + 3];
        words.push(word | 0); // 强制将结果转为 32 位有符号整数
    }

    // 构建结果对象
    var result = {
        sigBytes: byteArray.length,
        words: words,
    };

    return result;

}


function EVPKDF(password, salt) {
    // 配置信息
    const config = {
        keySize: 12,          // 密钥长度为 4 个字（32 位）
        hasher: CryptoJS.algo.MD5,  // 使用 MD5 作为哈希函数
        iterations: 1        // 迭代次数为 1
    };

    // 创建哈希函数实例
    const hasher = config.hasher.create();

    // 初始化 WordArray 对象
    const result = CryptoJS.lib.WordArray.create();

    // 获取 WordArray 对象的 words 数组
    const resultWords = result.words;

    l =  config.iterations;
    // 循环直到生成足够长度的密钥
    while (resultWords.length < config.keySize) {
        // 更新哈希函数
        hashResult = hasher.update(password).finalize(salt);
        // 重置哈希函数状态
        hasher.reset();
        hasher.update(hashResult);
        result.concat(hashResult);
    }

    // 设置最终结果的字节数
    result.sigBytes = 4 * config.keySize;
    return result;
}
s_random =function(t) {
    for (var n, r = [], i = function(t) {
        var n = 987654321,
            r = 4294967295;
        return function() {
            var i = ((n = 36969 * (65535 & n) + (n >> 16) & r) << 16) + (t = 18e3 * (65535 & t) + (t >> 16) & r) & r;
            return i /= 4294967296,
            (i += .5) * (Math.random() > .5 ? 1 : -1);  // 生成介于 -1 和 1 之间的随机数
        };
    }, a = 0; a < t; a += 4) {
        var s = i(4294967296 * (n || Math.random()));
        n = 987654071 * s(),
        r.push(4294967296 * s() | 0);
    }
    console.log(r)
    console.log(t)
    var salt = {
        sigBytes: t,
        words: r
    }
    return salt
}

clamp = function(t,n){
    t[n >>> 2] &= 4294967295 << 32 - n % 4 * 8,
    t.length = Math.ceil(n / 4)
  };

result_token=function(n,s) {
    var t =  r = [1398893684, 1701076831].concat(s.words).concat(n.words)
      , n = 32
      , r = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    clamp(t,n);
    for (var i = [], a = 0; a < n; a += 3)
        for (var o = (t[a >>> 2] >>> 24 - a % 4 * 8 & 255) << 16 | (t[a + 1 >>> 2]>> 24 - (a + 1) % 4 * 8 & 255) << 8 | t[a + 2 >>> 2] >>> 24 - (a + 2) % 4 * 8 & 255, s = 0; s < 4 && a + .75 * s < n; s++)
            i.push(r.charAt(o >>> 6 * (3 - s) & 63));
    var l = r.charAt(64);
    if (l)
        for (; i.length % 4; )
            i.push(l);
    return i.join("")
};



token=function(plaintext){
    // 示例用法
    s = s_random(8);
    // s={
    //     "words": [
    //         -1244053985,
    //         -1055520677
    //     ],
    //     "sigBytes": 8
    // };
    e = '123456781bcddfkpwefkoeprgpjgpte'
    key_ = EVPKDF(e,s)// 32字节密钥的十六进制表示
    key=key_.toString(CryptoJS.enc.Hex)
    key =key.slice(0, 64)
    iv_ = CryptoJS.lib.WordArray.create(key_.words.slice(8), 16);  // 16字节初始化向量的十六进制表示
    iv = iv_.toString(CryptoJS.enc.Hex)
    // 加密
    encryptedText = encrypt(plaintext, key, iv);
    console.log('Encrypted:', encryptedText);
    n =get_Buffer(encryptedText);
    result =result_token(n,s);
    console.log(result);
    return result;
}


acc = token('test')
pwd= token('test')
version = token('test')



// // 解密
// const decryptedText = decrypt(encryptedText, key, iv);
// console.log('Decrypted:', decryptedText);
