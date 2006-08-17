#! /bin/bash
lynx -nolist -dump http://fuse.sourceforge.net/wiki/index.php/SshfsFaq \
| sed -e '1,12d' -e '/____/,$d' > FAQ.txt
