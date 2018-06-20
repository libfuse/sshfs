Unreleased Changes
------------------

* Make utimens(NULL) result in timestamp "now" -- no more touched files
  dated 1970-01-01
* New `createmode` workaround.
* Fix `fstat` workaround regression.

Release 3.3.2 (2018-04-29)
--------------------------

* New `renamexdev` workaround.

Release 3.3.1 (2017-10-25)
--------------------------

* Manpage is now installed in correct directory.
* SSHFS now supports (or rather: ignores) some options that it may
  receive as result of being mounted from ``/etc/mtab``. This includes
  things like ``user``, ``netdev``, or ``auto``.

SSHFS 3.3.0 (2017-09-20)
------------------------

* Dropped support for writeback caching (and, as a consequence,
  "unreliable append" operation). As of kernel 4.14, the FUSE module's
  writeback implementation is not compatible with network filesystems
  and there are no imminent plans to change that.
* Add support for mounting from /etc/fstab
* Dropped support for building with autotools.
* Added missing options to man page.

Release 3.2.0 (2017-08-06)
--------------------------

* Re-enabled writeback cache.
* SSHFS now supports O_APPEND.

Release 3.1.0 (2017-08-04)
--------------------------

* Temporarily disabled the writeback cache feature, since there
  have been reports of dataloss when appending to files when
  writeback caching is enabled.

* Fixed a crash due to a race condition when listing
  directory contents.

* For improved backwards compatibility, SSHFS now also silently
  accepts the old ``-o cache_*`` options.
  
Release 3.0.0 (2017-07-08)
--------------------------

* sshfs now requires libfuse 3.1.0 or newer.
* When supported by the kernel, sshfs now uses writeback caching.
* The `cache` option has been renamed to `dir_cache` for clarity.  
* Added unit tests
* --debug now behaves like -o debug_sshfs, i.e. it enables sshfs
  debugging messages rather than libfuse debugging messages.
* Documented limited hardlink support.
* Added support for building with Meson.
* Added support for more SSH options.
* Dropped support for the *nodelay* workaround - the last OpenSSH
  version for which this was useful was released in 2006.
* Dropped support for the *nodelaysrv* workaround. The same effect
  (enabling NODELAY on the server side *and* enabling X11 forwarding)
  can be achieved by explicitly passing `-o ForwardX11`
* Removed support for `-o workaround=all`. Workarounds should always
  enabled explicitly and only when needed. There is no point in always
  enabling a potentially changing set of workarounds.
  
Release 2.9 (2017-04-17)
------------------------

* Improved support for Cygwin.
* Various small bugfixes.

Release 2.8 (2016-06-22)
------------------------

* Added support for the "fsync" extension.
* Fixed a build problem with bitbake

Release 2.7 (2016-03-01)
------------------------

* Integrated osxfuse's copy of sshfs, which means that sshfs now works
  on OS X out of the box.
* Added -o cache_max_size=N option to let users tune the maximum size of
  the cache in number of entries.
* Added -o cache_clean_interval=N and -o cache_min_clean_interval=N
  options to let users tune the cleaning behavior of the cache.

Release 2.6 (2015-01-28)
------------------------

* New maintainer (Nikolaus Rath <Nikolaus@rath.org>)

Release 2.5 (2014-01-14)
------------------------

* Some performance improvements for large directories.
* New `disable_hardlink` option.
* Various small bugfixes.

Release 2.4 (2012-03-08)
------------------------

* New `slave` option.
* New `idmap`, `uidmap` and `gidmap` options.  
* Various small bugfixes.

Release 2.3 (2011-07-01)
------------------------

* Support hard link creation if server is OpenSSH 5.7 or later
* Small improvements and bug fixes  
* Check mount point and options before connecting to ssh server
* New 'delay_connect' option

Release 2.2 (2008-10-20)
------------------------

* Handle numerical IPv6 addresses enclosed in square brackets
* Handle commas in usernames

Release 2.1 (2008-07-11)
------------------------

* Small improvements and bug fixes  

Release 2.0 (2008-04-23)
------------------------

* Support password authentication with pam_mount

* Support atomic renames if server is OpenSSH 4.9 or later

* Support getting disk usage if server is OpenSSH 5.1 or later

* Small enhancements and bug fixes

What is new in 1.9
------------------

* Fix a serious bug, that could result in sshfs hanging, crashing, or
  reporting out-of-memory

What is new in 1.8
------------------

* Bug fixes

What is new in 1.7
------------------

* Tolerate servers which print a banner on login

* Small improvements

What is new in 1.6
------------------

* Workaround for missing truncate operation on old sftp servers

* Bug fixes

What is new in 1.5
------------------

* Improvements to read performance.  Now both read and write
  throughput should be very close to 'scp'

* If used with FUSE 2.6.0 or later, then perform better data caching.
  This should show dramatic speed improvements when a file is opened
  more than once

* Bug fixes

What is new in 1.4
------------------

* Updated to version 25 of libfuse API

* This means that the 'cp' of readonly file to sshfs bug is finally
  solved (as long as using libfuse 2.5.0 or later *and* Linux 2.6.15
  or later)

* Sshfs now works on FreeBSD

* Added option to "transform" absolute symbolic links

What is new in 1.3
------------------

* Add workaround for failure to rename to an existing file

* Simple user ID mapping

* Estimate disk usage of files based on size

* Report "infinite" disk space

* Bug fixes

What is new in 1.2
------------------

* Better compatibility with different sftp servers

* Automatic reconnect (optional)

What is new in 1.1
------------------

* Performance improvements:

   - directory content caching

   - symlink caching

   - asynchronous writeback

   - readahead

* Fixed '-p' option

What is new in 1.0
------------------

* Initial release
