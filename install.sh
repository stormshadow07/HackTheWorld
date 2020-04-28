#!/bin/bash

arch=$(head -n1 /etc/issue | cut -d' ' -f1)

if [ -e /usr/bin/msfvenom ]; then
    printf "[] Msfvenom is already installed.\n"
elif [ "$arch" = "Kali" ]; then
	printf "[!] Msfvenom is not installed but this is Kali Linux.\n"
	printf "[*] The Metasploit framework is available as a package via:\n"
	printf "[*] apt install metasploit-framework\n"
else 
	printf "[!] Msfvenom is not installed at /usr/bin/msfvenom.\n"
	printf "[*] If it's already installed and on your path, ignore this warning.\n"
	printf "[*] Otherwise, you need to install the Metasploit framework (https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers).\n"
fi

if [ -e /usr/bin/wine ]; then
    printf "[] Wine is already installed.\n"
else 
	printf "[!] Wine is not installed.\n"
	printf "[*] Updating the apt cache.\n"
    sudo apt-get -qq update || exit 1
	
	printf "\n[*]Adding x86 architecture to x86_64 system for Wine.\n"
    sudo dpkg --add-architecture i386 || exit 1
	sudo apt-get install -y wine
	
	printf "Restart install.sh.\n"
	exit 1
fi

if [ -e /usr/bin/x86_64-w64-mingw32-gcc ]; then
    printf "[] Mingw-w64 Compiler is already installed.\n"
elif [ "$arch" = "Kali" ]; then
	for package in mingw-w64 mingw32; do
		sudo apt-get install -y $package
	done
else
	printf "[!] Compilation requires Mingw-w64.\n"
	printf "[!] Suggest using Kali Linux. Otherwise, you will need the mingw-w64 package.\n"
	printf "[!] You may also need mingw32 depending on the age of your distro.\n"
	printf "[*] Re-run install.sh when this is resolved.\n"
	exit 1
fi

printf "\nDependencies are installed successfully.\n"
printf "You can now execute by typing: \"python HackTheWorld.py\"\n"

exit 0
