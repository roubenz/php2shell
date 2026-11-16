#!/usr/bin/env python3
"""Minimal FastCGI client for the reference fpm lab (standalone, python3 -I).
Capability: POST a raw body with chosen headers to php-fpm on 127.0.0.1:PORT.
Mechanism: FCGI_BEGIN_REQUEST + FCGI_PARAMS + FCGI_STDIN; reads FCGI_STDOUT.
Constraints: single request/conn; lab use only."""
import socket, struct, sys, os, time

def _pair(k, v):
    k=k.encode() if isinstance(k,str) else k; v=v.encode() if isinstance(v,str) else v
    def L(n): return struct.pack("!I", n|0x80000000) if n>127 else bytes([n])
    return L(len(k))+L(len(v))+k+v

def _rec(t, rid, data=b""):
    out=bytearray()
    for i in range(0, max(1,len(data)), 65535):
        ch=data[i:i+65535]
        out+=struct.pack("!BBHHBx",1,t,rid,len(ch),0)+ch
    return bytes(out)

def request(port, params, body=b"", host="127.0.0.1", tries=80):
    rid=1
    last=None
    for _ in range(tries):
        try:
            s=socket.create_connection((host,port), timeout=240)
            s.sendall(struct.pack("!BBHHBx",1,1,rid,8,0)+struct.pack("!HBxxxxx",1,0)) # BEGIN
            p=b"".join(_pair(k,v) for k,v in params.items())
            s.sendall(_rec(4,rid,p)+_rec(4,rid,b""))      # PARAMS + end
            s.sendall(_rec(5,rid,body)+_rec(5,rid,b""))    # STDIN + end
            out=bytearray()
            while True:
                hdr=s.recv(8)
                if len(hdr)<8: break
                _,t,_,clen,plen,_=struct.unpack("!BBHHBB",hdr)
                data=b""
                while len(data)<clen+plen:
                    c=s.recv(clen+plen-len(data))
                    if not c: break
                    data+=c
                payload=data[:clen]
                if t==6: out+=payload       # STDOUT
                elif t==3: break            # END_REQUEST
            s.close()
            return bytes(out)
        except (ConnectionError, OSError) as e:
            last=e
            try: s.close()
            except Exception: pass
            time.sleep(0.05)
    return b"Status: 599 EXC\r\n\r\n"+repr(last).encode()

def wait_up(port, script="pid.php", tries=200):
    for _ in range(tries):
        out=request(port, {"GATEWAY_INTERFACE":"FastCGI/1.0","REQUEST_METHOD":"GET",
            "SCRIPT_FILENAME":"/var/www/html/"+script,"SCRIPT_NAME":"/"+script,
            "REQUEST_URI":"/"+script,"DOCUMENT_ROOT":"/var/www/html",
            "SERVER_PROTOCOL":"HTTP/1.1","REMOTE_ADDR":"127.0.0.1"}, tries=1)
        if b"PID" in out or b"OK" in out: return True
        time.sleep(0.1)
    return False

def post_multipart(port, script, parts, cookie=None, bnd=b"BND0"):
    from common.multipart import part, terminator   # shared encoder (byte-identical)
    body=b"".join(part(name,val,filename=fn,ctype="application/octet-stream",boundary=bnd)
                  for name,val,fn in parts)+terminator(bnd)
    params={"GATEWAY_INTERFACE":"FastCGI/1.0","REQUEST_METHOD":"POST",
            "SCRIPT_FILENAME":"/var/www/html/"+script,"SCRIPT_NAME":"/"+script,
            "REQUEST_URI":"/"+script,"DOCUMENT_ROOT":"/var/www/html","SERVER_PROTOCOL":"HTTP/1.1",
            "CONTENT_TYPE":"multipart/form-data; boundary="+bnd.decode(),
            "CONTENT_LENGTH":str(len(body)),"REMOTE_ADDR":"127.0.0.1"}
    if cookie: params["HTTP_COOKIE"]=cookie
    return request(port, params, body)

def get(port, script, qs="", cookie=None):
    params={"GATEWAY_INTERFACE":"FastCGI/1.0","REQUEST_METHOD":"GET",
            "SCRIPT_FILENAME":"/var/www/html/"+script,"SCRIPT_NAME":"/"+script,
            "REQUEST_URI":"/"+script+("?"+qs if qs else ""),"QUERY_STRING":qs,
            "DOCUMENT_ROOT":"/var/www/html","SERVER_PROTOCOL":"HTTP/1.1","REMOTE_ADDR":"127.0.0.1"}
    if cookie: params["HTTP_COOKIE"]=cookie
    return request(port, params)

if __name__=="__main__":
    port=int(sys.argv[1]); print(get(port,"pid.php").decode("latin1","replace"))
