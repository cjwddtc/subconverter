#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import cgi, cgitb
import base64
import requests
import re
import yaml
import urllib.parse
print("Content-type:text/yaml\n")
form = cgi.FieldStorage()
url=form.getvalue("url")
reg=form.getvalue("re")
a=requests.get(url)
a=a.content
a=base64.b64decode(a+ b'=' * (-len(a) % 4)).decode()
a=a.split('\n')
data=[]
for url in a:
    if len(url) != 0:
        a=re.match('ss://([^@]+)@([^:]+):([0-9]+)(/\\?plugin=(simple-obfs|obfs-local)%3B([^&+]+))?#(.*)',url)
        if a != None:
            a=a.groups()
            keys=base64.b64decode(a[0].encode()+b'=' * (-len(a[0]) % 4)).decode().split(':')
            #: obfs, plugin-opts: {mode: http, host: 4ad8b181d0.douyincdn.com}, udp: true
            proxy={
                "name":urllib.parse.unquote(a[-1]),
                "server":a[1],
                "port":a[2],
                "type": "ss",
                "cipher": keys[0],
                "password": keys[1]
            }
            if a[-2]!=None:
                b=urllib.parse.unquote(a[-2])
                params={str.split('=')[0]:str.split('=')[1] for str in b.split(';')}
                proxy["plugin"]="obfs"

                proxy["plugin-opts"]={
                    "mode":params["obfs"],
                    "host":params["obfs-host"]
                }
            data.append(proxy)
            continue
        a=re.match('trojan://([^@]+)@([^:]+):([0-9]+)\\?([^#]+)#(.*)',url)
        if a != None:
            a=a.groups()
            params={str.split('=')[0]:str.split('=')[1] for str in a[-2].split('&')}
            proxy={
                "name":urllib.parse.unquote(a[-1]),
                "server":a[1],
                "port":a[2],
                "type": "trojan",
                "password": a[0],
                "udp": True
            }
            if "allowInsecure" in params:
                proxy["skip-cert-verify"]=bool(params["allowInsecure"])
            if "sni" in params:
                proxy["sni"]=params["sni"]
            data.append(proxy)
            continue
data=[a for a in data if re.match(reg,a['name']) != None]
print(yaml.dump({"proxies":data}))
