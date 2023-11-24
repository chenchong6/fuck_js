import mitmproxy.http
import time

class JsCheckPass:
    def response(slef, flow: mitmproxy.http.HTTPFlow):
        if  'main.js' in flow.request.url:
            print(flow.request.url)
            print(111111111)
            print(flow.response.text)
            time.sleep(1)
            flow.response.text = flow.response.text.replace('Wt("aesKey",t)',
                                                            'Wt("aesKey","sCqio4GD1OpokqELEq3nlssmjaoefhRb")')
            flow.response.set_text(flow.response.text)

addons = [
    JsCheckPass(),
]
