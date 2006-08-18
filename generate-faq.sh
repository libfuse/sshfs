#! /bin/bash

(
echo "See http://fuse.sourceforge.net/wiki/index.php/SshfsFaq for the latest"
echo "version of this FAQ"
echo "---"
echo

lynx -nolist -dump http://fuse.sourceforge.net/wiki/index.php/SshfsFaq \
| sed -e '1,12d' -e '/____/,$d'
) > FAQ.txt
