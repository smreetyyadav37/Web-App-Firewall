
import http.client  # httplib was renamed to http.client in Python 3
import re
import io  # StringIO was moved to io in Python 3
import gzip

class RawWeb:
    def __init__(self, raw):
        try:
            raw = raw.decode('utf-8') if isinstance(raw, bytes) else raw
        except Exception as e:
            print(f"Error decoding raw input: {e}")
        
        global headers, method, body, path
        headers = {}
        
        sp = raw.split('\n\n', 1)
        if len(sp) > 1:
            head = sp[0]
            body = sp[1]
        else:
            head = sp[0]
            body = ""
        
        c1 = head.split('\n')
        method = c1[0].split(' ', 2)[0]
        path = c1[0].split(' ', 2)[1]
        
        for i in range(1, len(c1)):
            slice1 = c1[i].split(': ', 1)
            if len(slice1) == 2:
                headers[slice1[0]] = slice1[1]

    def rebuild(self, method, path, code, headers, body):
        raw_stream = f"{method} {path} {code}\n"
        for key, value in headers.items():
            raw_stream += f"{key}: {value}\n"
        raw_stream += f"\n{body}"
        return raw_stream

    def addheaders(self, new_header):
        for key, value in new_header.items():
            headers[key] = value
        return self.rebuild(method, path, "HTTP/1.1", headers, body)

    def removeheaders(self, rem_headers):
        for header in rem_headers:
            headers.pop(header, None)
        return self.rebuild(method, path, "HTTP/1.1", headers, body)

    def addparameters(self, new_params):
        global body
        new_body = body[:-1] if body else ""
        for key, value in new_params.items():
            new_body += f"&{key}={value}"
        body = new_body
        return self.rebuild(method, path, "HTTP/1.1", headers, body)

    def removeparameter(self, del_param):
        global body
        rx = f'(^|&){del_param}=[^&]*'
        body = re.sub(rx, '', body)
        return self.rebuild(method, path, "HTTP/1.1", headers, body)

    def changemethod(self):
        global method, path, body
        if method == "POST":
            if "Content-Type" in headers:
                del headers['Content-Type']
            url = path
            url += "&" if "=" in url else "?"
            url += body[:-1]
            method, path, body = "GET", url, ""
            return self.rebuild("GET", url, "HTTP/1.1", headers, body)
        else:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            url = path.split('?', 1)[0]
            method, path, body = "POST", url, path.split('?', 1)[1]
            return self.rebuild("POST", url, "HTTP/1.1", headers, body)

    def craft_res(self, res_head, res_body):
        for e1 in res_head:
            if e1[1] == "gzip":
                res_body = self.decode_gzip(res_body)
        return res_body

    def decode_gzip(self, compresseddata):
        compressedstream = io.BytesIO(compresseddata)
        with gzip.GzipFile(fileobj=compressedstream) as gzipper:
            return gzipper.read().decode('utf-8')

    def fire(self, ssl="off"):
        print(f"[+] {method} {path[:100]}..." if len(path) > 70 else f"[+] {method} {path}")
        
        if ssl == "on":
            conn = http.client.HTTPSConnection(headers['Host'])
        else:
            conn = http.client.HTTPConnection(headers['Host'])
        
        try:
            conn.request(method, path, body, headers)
            res = conn.getresponse()
        except Exception as e:
            print(f"[+] Connectivity Issue: {e}")
            return 'Error', 'Error', {}, 'Error'
        
        res_headers = dict(res.getheaders())
        return res.status, res.reason, res_headers, self.craft_res(res.getheaders(), res.read())

