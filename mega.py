# coding=utf-8
from base64 import b64decode
from urllib import request
import json
import struct
import sys
import pycurl
from io import BytesIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

aes_backend = default_backend()
AES_BLOCK_SIZE = 16
chunk_size = 16 << 20  # 16M
USING_IPV6 = True

curl_share = pycurl.CurlShare()
curl_share.setopt(pycurl.SH_SHARE, pycurl.LOCK_DATA_DNS)
curl_share.setopt(pycurl.SH_SHARE, pycurl.LOCK_DATA_SSL_SESSION)
Cache = {}

def post(url, f=None, post_data=None,c=None):
    if f is None:
        buffer = BytesIO()
        post(url,buffer,post_data)
        return buffer.getvalue()
    cleanup = False
    if c is None:
        c = pycurl.Curl()
        c.setopt(pycurl.SHARE, curl_share)
        cleanup = True
    if post_data:
        c.setopt(pycurl.POSTFIELDS, post_data)
    c.setopt(pycurl.CUSTOMREQUEST, 'POST')
    if USING_IPV6:
       c.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V6)
    c.setopt(pycurl.WRITEDATA, f)
    c.setopt(pycurl.URL, url)
    #c.setopt(pycurl.VERBOSE, True)
    c.setopt(pycurl.SSL_VERIFYPEER, False)

    c.perform()
    if cleanup:
        c.close()


def bytes_xor(a, b):
    return bytes([(i ^ j) for (i, j) in zip(a, b)])


def unpack_node_key(k):
    return bytes_xor(k[0:16], k[16:32]), k[16:24] + b'\0' * 8, k[24:32]


def padding_base64(x):
    return x + "=" * (4 - (len(x) % 4))


class AesFile:
    def __init__(self,_f,_aes):
        self.f = _f
        self.aes = _aes

    def write(self,data):
        self.f.write(self.aes.update(data))


def downland_url(_arg, f, dr=None):
    url, file_size, aes_key, aes_vi = _arg
    if dr is None:
        dr = [0, file_size - 1]  # [a,b)
    if len(dr) == 1 or dr[1] > file_size - 1:
        dr[1] = file_size - 1
    dr[1] += 1
    chunk = (dr[0], min(dr[0] + chunk_size, dr[1]))
    aes_vi = aes_vi[0:8] + struct.pack(">Q", dr[0] // AES_BLOCK_SIZE)
    aes = Cipher(algorithms.AES(aes_key), modes.CTR(aes_vi), backend=aes_backend).decryptor()
    aes.update(b'\0' * (dr[0] % AES_BLOCK_SIZE))
    aesfile = AesFile(f,aes)

    c = pycurl.Curl()
    c.setopt(pycurl.SHARE, curl_share)

    while chunk[0] < dr[1]:
        req = post(url + ("/%d-%d" % (chunk[0], chunk[1] - 1)),aesfile,None,c)
        chunk = (chunk[1], min(chunk[1] + chunk_size, dr[1]))
        print(chunk[0])

    c.close()
    aes.finalize()


def downland_info(handle, key):
    #print(handle)

    if handle in Cache:
        return Cache[handle]

    key = b64decode(padding_base64(key), "-_")

    resp =  post('https://g.api.mega.co.nz/cs?id=0&domain=meganz',
                post_data=json.dumps([{"a": "g", "g": "1", "p": handle, "ssl": "0"}]).encode() )

    j = json.loads(resp.decode())[0]
    if isinstance(j, int):
        raise Exception("ERROR %d" % (j,))

    at = b64decode(padding_base64(j["at"]), "-_")
    aes_key, aes_vi, mac = unpack_node_key(key)
    decryptor_cbc = Cipher(algorithms.AES(aes_key), modes.CBC(b'\0' * 16), backend=aes_backend).decryptor()
    at = decryptor_cbc.update(at) + decryptor_cbc.finalize()

    if not at.startswith(b"MEGA"):
        raise Exception("can't read at")
    at = json.loads(at[4:].strip(b'\0').decode())

    Cache[handle] = (at["n"], j["s"], (j["g"], j["s"], aes_key, aes_vi))

    return Cache[handle]


def main(qs, f=None):
    handle, key = qs.split("!")[1:]

    assert (len(handle) == 8 and len(key) == 43)
    fname, fsize, dl_arg = downland_info(handle, key)
    print(fname, fsize)
    if f is None:
        f = open(fname,"wb")
    downland_url(dl_arg, f)


if __name__ == "__main__":
    main(sys.argv[1])
