└─$ `whatis cadaver`
cadaver (1)          - A command-line WebDAV client for Unix.



root@attackdefense:~# `cadaver -help`
Usage: cadaver [OPTIONS] http://hostname[:port]/path
  Port defaults to 80, path defaults to '/'
Options:
  -t, --tolerant            Allow cd/open into non-WebDAV enabled collection.
  -r, --rcfile=FILE         Read script from FILE instead of ~/.cadaverrc.
  -p, --proxy=PROXY[:PORT]  Use proxy host PROXY and optional proxy port PORT.
  -V, --version             Display version information.
  -h, --help                Display this help message.
Please send bug reports and feature requests to <cadaver@webdav.org>
root@attackdefense:~# `cadaver`
dav:!> `help`
Available commands: 
 ls         cd         pwd        put        get        mget       mput       
 edit       less       mkcol      cat        delete     rmcol      copy       
 move       lock       unlock     discover   steal      showlocks  version    
 checkin    checkout   uncheckout history    label      propnames  chexec     
 propget    propdel    propset    search     set        open       close      
 echo       quit       unset      lcd        lls        lpwd       logout     
 help       describe   about      
Aliases: rm=delete, mkdir=mkcol, mv=move, cp=copy, more=less, quit=exit=bye
dav:!> 
