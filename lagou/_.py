# -*- coding: utf-8 -*-
import json
from lagou_Encrypt import generatekey, Encrypt
import requests, re, execjs, demjson, time
from lxml import etree

r = requests.session()


def get_user_trace_token():
    headers = {
        "Host": "a.lagou_add_task.com",
        "Referer": "https://www.lagou.com/",
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'

    }
    json_url = 'https://a.lagou.com/json'
    params = {
        "lt": "trackshow",
        "t": "ad",
        "v": 0,
        "dl": "https://www.lagou.com/",
        "dr": "https://www.lagou.com",
        "time": str(int(time.time() * 1000))
    }
    response = requests.get(url=json_url, headers=headers, params=params)
    user_trace_token = response.cookies.get_dict()["user_trace_token"]
    print(user_trace_token)
    return user_trace_token


def get_x_http_token(user_trace_token):
    lg_js = '''function getXHttpToken(cookie){
    var document = {
        "cookie": cookie,
    }
    var _0x1f67 = ['documentElement', 'body', 'scrollLeft', 'clientLeft', 'clientY', 'scrollTop', 'clientTop', 'pageX', 'pageY', 'floor', 'random', 'trackImage_', 'onload', 'onerror', 'src', 'XMLHttpRequest', 'Microsoft', 'open', 'GET', '/wafcheck.json', 'send', 'getResponseHeader', 'replace', 'parse', 'substring', 'utrack', 'location', 'protocol', 'hostname', 'getTime', 'push', 'https://', 'host', '/utrack/track.gif', 'user_trace_token', 'X_HTTP_TOKEN', 'length', 'fromCharCode', 'concat', 'charAt', 'HTTP_JS_KEY', '(^|\x20)', '=([^;]*)(;|$)', 'cookie', 'match', '=;\x20expires=Thu,\x2001\x20Jan\x201970\x2000:00:00\x20UTC;\x20path=/;', 'event', 'tagName', 'BUTTON', 'INPUT', 'hidden-form-send', 'className', 'indexOf', 'target', 'srcElement', 'parentNode', 'log', 'clientX', 'ownerDocument'];
    (function(_0x4bd822, _0x2bd6f7) {
        var _0xb4bdb3 = function(_0x1d68f6) {
        };
        _0xb4bdb3(++_0x2bd6f7);
    }(_0x1f67, 0x14b))
    var _0x3551 = function(_0x1e41ca, _0x165168) {
        _0x1e41ca = _0x1e41ca - 0x0;
        var _0x122898 = _0x1f67[_0x1e41ca];
        return _0x122898;
    };
    function _0xf848b6(_0x4fbd64, _0x42cba3) {
        var _0x19e6d = (_0x4fbd64 & 0xffff) + (_0x42cba3 & 0xffff);
        var _0x1729b3 = (_0x4fbd64 >> 0x10) + (_0x42cba3 >> 0x10) + (_0x19e6d >> 0x10);
        return _0x1729b3 << 0x10 | _0x19e6d & 0xffff;
    }
    function _0x670f4d(_0x4dc328, _0x25a720) {
        return _0x4dc328 << _0x25a720 | _0x4dc328 >>> 0x20 - _0x25a720;
    }
    function _0x2739f7(_0x1dea7d, _0x130596, _0x14480f, _0x596e8d, _0x2c995c, _0x22a611) {
        return _0xf848b6(_0x670f4d(_0xf848b6(_0xf848b6(_0x130596, _0x1dea7d), _0xf848b6(_0x596e8d, _0x22a611)), _0x2c995c), _0x14480f);
    }
    function _0xaa05ae(_0x2c21c6, _0x45bd1c, _0xc01eb5, _0x3ac73d, _0xecc463, _0x45185e, _0x36b67f) {
        return _0x2739f7(_0x45bd1c & _0xc01eb5 | ~_0x45bd1c & _0x3ac73d, _0x2c21c6, _0x45bd1c, _0xecc463, _0x45185e, _0x36b67f);
    }
    function _0x5a5634(_0x458dc9, _0x5a0340, _0xc0ee78, _0x2d51a1, _0x2c66d6, _0x7ade00, _0x53f7cf) {
        return _0x2739f7(_0x5a0340 & _0x2d51a1 | _0xc0ee78 & ~_0x2d51a1, _0x458dc9, _0x5a0340, _0x2c66d6, _0x7ade00, _0x53f7cf);
    }
    function _0x5d8807(_0x458674, _0x27821e, _0x26d3ea, _0x54241a, _0x2022a3, _0x62b675, _0x2b7662) {
        return _0x2739f7(_0x27821e ^ _0x26d3ea ^ _0x54241a, _0x458674, _0x27821e, _0x2022a3, _0x62b675, _0x2b7662);
    }
    function _0x318283(_0x3ff4d5, _0x48a086, _0x2a0228, _0x3f383b, _0x138e36, _0x35b7c8, _0x5bd9b4) {
        return _0x2739f7(_0x2a0228 ^ (_0x48a086 | ~_0x3f383b), _0x3ff4d5, _0x48a086, _0x138e36, _0x35b7c8, _0x5bd9b4);
    }
    function _0x45e748(_0x514574, _0x5ddbd2) {
    }
    function _0x1b432e(_0x318f27) {
        var _0x213d40;
        var _0x5ee7f7 = '';
        var _0x56884a = _0x318f27[_0x3551('0x0')] * 0x20;
        for (_0x213d40 = 0x0; _0x213d40 < _0x56884a; _0x213d40 += 0x8) {
            _0x5ee7f7 += String[_0x3551('0x1')](_0x318f27[_0x213d40 >> 0x5] >>> _0x213d40 % 0x20 & 0xff);
        }
        return _0x5ee7f7;
    }
    function _0x10ffc6(_0x2ece02) {
        var _0x43844c;
        var _0x116949 = [];
        _0x116949[(_0x2ece02[_0x3551('0x0')] >> 0x2) - 0x1] = undefined;
        for (_0x43844c = 0x0; _0x43844c < _0x116949['length']; _0x43844c += 0x1) {
            _0x116949[_0x43844c] = 0x0;
        }
        var _0x26257e = _0x2ece02[_0x3551('0x0')] * 0x8;
        for (_0x43844c = 0x0; _0x43844c < _0x26257e; _0x43844c += 0x8) {
            _0x116949[_0x43844c >> 0x5] |= (_0x2ece02['charCodeAt'](_0x43844c / 0x8) & 0xff) << _0x43844c % 0x20;
        }
        return _0x116949;
    }
    function _0x3e2628(_0x32569f) {
        return _0x1b432e(_0x45e748(_0x10ffc6(_0x32569f), _0x32569f[_0x3551('0x0')] * 0x8));
    }
    function _0x56a776(_0xcb72a2, _0x52982d) {
        var _0x248c33;
        var _0x21838a = _0x10ffc6(_0xcb72a2);
        var _0x3e451e = [];
        var _0x4e5594 = [];
        var _0x350fc7;
        _0x3e451e[0xf] = _0x4e5594[0xf] = undefined;
        if (_0x21838a[_0x3551('0x0')] > 0x10) {
            _0x21838a = _0x45e748(_0x21838a, _0xcb72a2[_0x3551('0x0')] * 0x8);
        }
        for (_0x248c33 = 0x0; _0x248c33 < 0x10; _0x248c33 += 0x1) {
            _0x3e451e[_0x248c33] = _0x21838a[_0x248c33] ^ 0x36363636;
            _0x4e5594[_0x248c33] = _0x21838a[_0x248c33] ^ 0x5c5c5c5c;
        }
        _0x350fc7 = _0x45e748(_0x3e451e[_0x3551('0x2')](_0x10ffc6(_0x52982d)), 0x200 + _0x52982d[_0x3551('0x0')] * 0x8);
        return _0x1b432e(_0x45e748(_0x4e5594[_0x3551('0x2')](_0x350fc7), 0x200 + 0x80));
    }
    function _0x4476e5(_0x5e7bd4) {
        var _0x25745a = '0123456789abcdef';
        var _0x1bb4fd = '';
        var _0x5a1951;
        var _0xf4d402;
        for (_0xf4d402 = 0x0; _0xf4d402 < _0x5e7bd4[_0x3551('0x0')]; _0xf4d402 += 0x1) {
            _0x5a1951 = _0x5e7bd4['charCodeAt'](_0xf4d402);
            _0x1bb4fd += _0x25745a[_0x3551('0x3')](_0x5a1951 >>> 0x4 & 0xf) + _0x25745a[_0x3551('0x3')](_0x5a1951 & 0xf);
        }
        return _0x1bb4fd;
    }
    function _0x37d7f1(_0x3321b5) {
        return unescape(encodeURIComponent(_0x3321b5));
    }
    function _0x4897ab(_0x1f3964) {
        return _0x3e2628(_0x37d7f1(_0x1f3964));
    }
    function _0x5c9998(_0x42d437) {
        return _0x4476e5(_0x4897ab(_0x42d437));
    }
    function _0x413677(_0x32cd7a, _0x5f3088) {
        return _0x56a776(_0x37d7f1(_0x32cd7a), _0x37d7f1(_0x5f3088));
    }
    function _0x15476b(_0x300820, _0x5861df) {
        return _0x4476e5(_0x413677(_0x300820, _0x5861df));
    }
    function _0x1c7889(_0x109e42, _0x434a83, _0x3c243f) {
        if (!_0x434a83) {
            if (!_0x3c243f) {
                return _0x5c9998(_0x109e42);
            }
            return _0x4897ab(_0x109e42);
        }
        if (!_0x3c243f) {
            return _0x15476b(_0x434a83, _0x109e42);
        }
        return _0x413677(_0x434a83, _0x109e42);
    }
    function _0x515c70(_0x503154) {
        var _0xacc7f7, _0x126261 = new RegExp(_0x3551('0x5') + _0x503154 + _0x3551('0x6'));
        if (_0xacc7f7 = document[_0x3551('0x7')][_0x3551('0x8')](_0x126261))
            return unescape(_0xacc7f7[0x2]);
        else
            return '';
    }
    function _0x89ea42() {
        var _0x150c4d = new Date();
        var _0x4e6d5d = Date.parse(_0x150c4d);
        return _0x4e6d5d / 0x3e8;
    }
    function _0x55bae5(_0x36a60f, _0x37fe42, _0x903bc9) {
        var _0x265f92 = _0x36a60f['substring'](0x0, _0x903bc9);
        var _0x3d1b53 = _0x36a60f['substring'](_0x903bc9, 0x20);
        return _0x265f92 + _0x37fe42 + _0x3d1b53;
    }
    function _0x39990b(_0x1472c1) {
        var _0x417e56 = '';
        for (var _0x5521d9 = _0x1472c1[_0x3551('0x0')] - 0x1; _0x5521d9 >= 0x0; _0x5521d9--) {
            _0x417e56 += _0x1472c1[_0x3551('0x3')](_0x5521d9);
        }
        return _0x417e56;
    }
    var _0x1bd82b = _0x3551('0x4');
    var _0x4bef56 = _0x515c70(_0x3551('0x39'));
    var _0x5c6712 = _0x1c7889(_0x1bd82b + _0x4bef56);
    var _0x597b06 = _0x89ea42();
    var _0x179ec1 = _0x55bae5(_0x5c6712, _0x597b06, 0x10);
    var _0x32e0d2 = _0x39990b(_0x179ec1);
    return _0x32e0d2
}
'''
    X_HTTP_TOKEN = execjs.compile(lg_js).call("getXHttpToken", "user_trace_token=" + user_trace_token)
    return X_HTTP_TOKEN


def get_lg_stoken(url):
    r.headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Pragma': 'no-cache',
        'Upgrade-Insecure-Requests': '1',
        'Connection': 'keep-alive',
        'Host': 'www.lagou.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
    }
    res = r.get(url, allow_redirects=True)
    r.headers['Referer'] = res.url
    X_HTTP_TOKEN = dict(r.cookies).get('X_HTTP_TOKEN')

    pat = re.compile(r'seed=(.*?)&')
    seed = ''.join(pat.findall(res.url))
    pat = re.compile(r'ts=(.*?)&')
    ts = ''.join(pat.findall(res.url))
    pat = re.compile(r'name=(.*?)&')
    name = ''.join(pat.findall(res.url))
    search_url = f"?{res.url.split('?')[-1]}"
    js_url = f'https://www.lagou.com/common-sec/dist/{name}.js'
    res = r.get(js_url)
    lg_js = '''window = {"location": {"hostname": "www.lagou.com","search": "%s"}};function getLgStoken(){return window.gt.prototype.a()};''' % (
        search_url) + res.text
    lg_stoken = execjs.compile(lg_js).call("getLgStoken")
    print(lg_stoken)
    cookie_item = {'__lg_stoken__': lg_stoken, }

    return cookie_item


def get_traceparent():
    exe_js = '''getRandomValues = require('get-random-values')

function E(t) {
    for (var b = [], w = 0; w < 256; ++w)
            b[w] = (w + 256).toString(16).substr(1);
    var T = new Uint8Array(16);
    return function(t) {
        for (var e = [], n = 0; n < t.length; n++)
            e.push(b[t[n]]);
        return e.join("")
    }(getRandomValues(T)).substr(0, t)
}

function getTraceparent(){
    return "00-" + E() + "-" + E(16) + "-" + "01"
}'''
    traceparent_id = execjs.compile(exe_js).call('getTraceparent')
    print(traceparent_id)
    return traceparent_id


def X_K_Header(aesKey):
    r.headers = {
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept-Language': 'zh-CN,zh;q=0.9',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Pragma': 'no-cache',
                    'Host': 'gate.lagou_add_task.com',
                    'Origin': 'https://www.lagou.com',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
                },
    pemfile = 'rsa_pubkey.pem'
    aes_iv = 'c558Gq0YQK2QUlMc'
    secret = Encrypt(aesKey, aes_iv)
    rsaEncryptData = secret.rsa_encrypt(aesKey.encode(), pemfile)
    url = 'https://gate.lagou.com/system/agreement'
    data = {'secretKeyDecode': rsaEncryptData}
    res = r.post(url, json=data)
    resp = json.loads(res.text)
    secretKeyValue = resp.get('content').get('secretKeyValue')
    return secretKeyValue


def get_X_S_HEADER(aesKey, origin_data):
    lg_js = '''CryptoJS = require('crypto-js')

jt = function(aesKey, originalData, u) {
    var e = {deviceType: 1}
      , t = "".concat(JSON.stringify(e)).concat(u).concat(JSON.stringify(originalData))
      , t = (t = t, null === (t = CryptoJS.SHA256(t).toString()) || void 0 === t ? void 0 : t.toUpperCase());

    return Rt(JSON.stringify({
        originHeader: JSON.stringify(e),
        code: t
    }), aesKey)
}

Rt = function (t, aesKey) {
    var Ot = CryptoJS.enc.Utf8.parse("c558Gq0YQK2QUlMc"),
        Dt = CryptoJS.enc.Utf8.parse(aesKey),
        t = CryptoJS.enc.Utf8.parse(t);
    t = CryptoJS.AES.encrypt(t, Dt, {
        iv: Ot,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return t.toString()
};

function getXSHeader(aesKey, originalData, u){
    return jt(aesKey, originalData, u)
}
'''
    url = "https://www.lagou.com/jobs/v2/positionAjax.json"
    X_S_HEADER = execjs.compile(lg_js).call("getXSHeader", aesKey, origin_data, url)
    return X_S_HEADER


def get_data(Traceparent, X_K_Header, X_S_Header, cook, aesKey, origin_data, Referer):
    lg_js = '''CryptoJS = require('crypto-js')

function getRequestData(aesKey, originalData){
    return Rt(JSON.stringify(originalData), aesKey)
}

function getResponseData(encryptData, aesKey){
    return It(encryptData, aesKey)
}

Rt = function (t, aesKey) {
    var Ot = CryptoJS.enc.Utf8.parse("c558Gq0YQK2QUlMc"),
        Dt = CryptoJS.enc.Utf8.parse(aesKey),
        t = CryptoJS.enc.Utf8.parse(t);
    t = CryptoJS.AES.encrypt(t, Dt, {
        iv: Ot,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return encodeURIComponent(decodeURIComponent(t.toString()));
};

It = function(t, aesKey) {
    var Ot = CryptoJS.enc.Utf8.parse("c558Gq0YQK2QUlMc"),
    Dt = CryptoJS.enc.Utf8.parse(aesKey);
    t = CryptoJS.AES.decrypt(t, Dt, {
        iv: Ot,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    }).toString(CryptoJS.enc.Utf8);
    try {
        t = JSON.parse(t)
    } catch (t) {}
    return t
}
'''
    r.headers = {
        'Referer': Referer,
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Host': 'www.lagou_add_task.com',
        'Traceparent': Traceparent,
        'X-K-Header': X_K_Header,
        'X-S-Header': X_S_Header,
        'X-Ss-Req-Header': json.dumps({'secret': X_K_Header}),
        'Origin': 'https://www.lagou.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
    }

    url = 'https://www.lagou.com/jobs/v2/positionAjax.json'
    payload = execjs.compile(lg_js).call('getRequestData', aesKey, origin_data)
    postdata = f'data={payload}'
    print(postdata)
    res = r.post(url, data=postdata, cookies=cook)
    resp = json.loads(res.text)
    resp = execjs.compile(lg_js).call('getResponseData', resp['data'], aesKey)
    print(resp)


if __name__ == '__main__':
    url = 'https://www.lagou.com/gongsi/v1/e7d635773cb9808874c0ef76096a630ae4d54247e1d8daa6816615707c21aa48.html'

    cookie_ = get_lg_stoken(url)
    res = r.get(url, cookies=cookie_)
    resp = etree.HTML(res.text)
    companyInfoData = resp.xpath('//script[@id="companyInfoData"]/text()')
    companyInfoData = json.loads(companyInfoData[0]) if companyInfoData else None
    company_interview_experiences = []
    if companyInfoData:
        company_industry = ''
        company_size = ''
        company_area = ''
        company_finance_stage = ''
        company_recruit_num = ''
        company_school_recruit_num = ''
        company_leaders = []
        company_logo = ''
        company_name = ''
        company_full_name = ''
        company_url = ''
        company_introduce = ''
        company_products = []
        company_labels = ''
        company_address = []
        company_desc = ''
        company_picture = ''
        company_type = ''
        business_legal_person = ''
        business_create_time = ''
        business_registered_address = ''
        business_registered_capital = ''
        business_registered_location = ''
        business_uniform_credit_id = ''
        business_external_url = ''
        business_regstatus=''
        baseInfo = companyInfoData.get('baseInfo')
        if baseInfo:
            company_industry = baseInfo.get('industryField')
            company_size = baseInfo.get('companySize')
            company_area = baseInfo.get('city')
            company_finance_stage = baseInfo.get('financeStage')
        dataInfo = companyInfoData.get('dataInfo')
        if dataInfo:
            positionCount = dataInfo.get('positionCount')
            schoolPositionCount = dataInfo.get('schoolPositionCount')
            company_recruit_num = positionCount
            company_school_recruit_num = schoolPositionCount

        leaders = companyInfoData.get('leaders')
        if leaders:
            leaders_new=[]
            for i in leaders:
                if i.get('photo'):
                    i['photo']  =  'https://www.lgstatic.com/thumbnail_200x200/{0}'.format(i['photo'])
                    leaders_new.append(i)
            company_leaders = leaders_new

        coreInfo = companyInfoData.get('coreInfo')
        if coreInfo:
            company_logo = 'https://www.lgstatic.com/{0}'.format(coreInfo.get('logo'))
            company_name = coreInfo.get('companyShortName')
            company_full_name = coreInfo.get('companyName')
            company_url = coreInfo.get('companyUrl')
            company_introduce = coreInfo.get('companyIntroduce')

        company_products = companyInfoData.get('products')
        company_labels = ','.join(companyInfoData.get('labels'))
        company_address = companyInfoData.get('addressList')
        introduction = companyInfoData.get('introduction')
        if introduction:
            company_desc = introduction.get('companyProfile')
            company_picture = introduction.get('pictures')

        companyBusinessInfo = companyInfoData.get('companyBusinessInfo')
        if companyBusinessInfo:
            company_type = companyBusinessInfo.get('companyType')
            business_legal_person = companyBusinessInfo.get('legalPersonName')
            business_create_time = companyBusinessInfo.get('establishTime')
            business_registered_address = companyBusinessInfo.get('regLocation')
            business_regstatus = companyBusinessInfo.get('regStatus')
            business_registered_location = companyBusinessInfo.get('regCapital')
            business_uniform_credit_id = companyBusinessInfo.get('creditCode')
            business_external_url = companyBusinessInfo.get('externalUrl')
    interviewExperiencesData = resp.xpath('//script[@id="interviewExperiencesData"]/text()')
    interviewExperiencesData = json.loads(interviewExperiencesData[0]) if interviewExperiencesData else None
    result = interviewExperiencesData.get('result')
    company_interview_experiences = result
    items = {'company_industry': company_industry, 'company_size': company_size, 'company_area': company_area,
             'company_finance_stage': company_finance_stage, 'company_recruit_num': company_recruit_num,
             'company_school_recruit_num': company_school_recruit_num, 'company_leaders': company_leaders,
             'company_logo': company_logo, 'company_name': company_name, 'company_full_name': company_full_name,
             'company_url': company_url,
             'company_introduce': company_introduce, 'company_products': company_products,
             'company_labels': company_labels,
             'company_address': company_address, 'company_desc': company_desc, 'company_picture': company_picture,
             'company_type': company_type, 'business_legal_person': business_legal_person,
             'business_create_time': business_create_time, 'business_registered_address': business_registered_address,
             'business_registered_capital': business_registered_capital,
             'business_registered_location': business_registered_location,'business_regstatus':business_regstatus,
             'business_uniform_credit_id': business_uniform_credit_id, 'business_external_url': business_external_url,
             'company_interview_experiences': company_interview_experiences}
    print(items)
    # user_trace_token = get_user_trace_token()
    # # x_http_token = get_x_http_token(user_trace_token)
    # cookie_['user_trace_token'] = user_trace_token
    # # # cookie_['X_HTTP_TOKEN']   = x_http_token
    # #
    # aes_iv = 'c558Gq0YQK2QUlMc'
    # aesKey = generatekey(32)
    # X_K_Header = X_K_Header(aesKey)
    # origin_data = {'first': 'true', 'needAddtionalResult': 'false', 'city': '上海', 'pn': '3', 'kd': 'PHP'}
    # X_S_Header = get_X_S_HEADER(aesKey, origin_data)
    # Traceparent = get_traceparent()
    # get_data(Traceparent, X_K_Header, X_S_Header, cookie_, aesKey, origin_data,url )
    #
    # # get_rsaEncryptData()
