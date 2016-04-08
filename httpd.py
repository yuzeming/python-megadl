# coding=utf-8
import socketserver
from http.server import HTTPStatus,BaseHTTPRequestHandler
from mega import downland_info,downland_url
from urllib.parse import quote
import socket


#from pprint import pprint

class Handler(BaseHTTPRequestHandler):
    def sand_head(self):
        #pprint(dict(self.headers))

        handle, key = self.path.split("!")[1:]
        if len(handle) != 8 or len(key) != 43:
            raise Exception("handle len must be 8 and key len must be 42")

        fname, fsize, dl_arg = downland_info(handle, key)
        dr = None
        if "Range" in self.headers:
            dr = [int(x) for x in self.headers["Range"][6:].split("-")]
            if len(dr) == 1:
                dr[1] = fsize
            self.send_response(HTTPStatus.PARTIAL_CONTENT)
            self.send_header("Content-Range", "bytes %d-%d/%d" % (dr[0], dr[1], fsize))
            self.send_header("Content-Length", dr[1]-dr[0]+1)
        else:
            self.send_response(HTTPStatus.OK)
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", fsize)
        
        self.send_header("Content-Transfer-Encoding", "binary")
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition",
                         "attachment; filename*=UTF-8''" + quote(fname.encode(), safe=""))

        self.end_headers()

        return dl_arg,dr

    def do_HEAD(self):
        self.sand_head()

    def do_GET(self):
        try:
            dl_arg,dr = self.sand_head()
            downland_url(dl_arg, self.wfile,dr)
        except Exception as e:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            self.wfile.write(str(e).encode())

USING_IPV6 = True
PORT = 8000
		
def main():
    bind_addr = ("0.0.0.0", PORT)
    if USING_IPV6:
       bind_addr = ("::", PORT) 
       socketserver.ThreadingTCPServer.address_family = socket.AF_INET6
    httpd = socketserver.ThreadingTCPServer(bind_addr, Handler)
    print("serving at port", PORT)
    httpd.serve_forever()

if __name__ == "__main__":
    main()