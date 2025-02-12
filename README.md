# mod-jail
Running Apache HTTP server in jail/chroot can be tricky, this module allows to run Apache in a secure jail prison easy, without creating real jail environment containing copy of /lib, /libexec, /usr/lib, etc. Also, every jail has it's own [securelevel](http://www.freebsd.org/doc/en/books/faq/security.html#SECURELEVEL), and if you use [file flags](http://www.freebsd.org/cgi/man.cgi?query=chflags&sektion=2&apropos=0), it is possible to make some file can be changed only outside jail, even root in jail can't delete or modify file.
**mod\_jail** is included in the official [FreeBSD's ports tree](https://www.freshports.org/www/mod_jail/).

There are two ways to run Apache in jail that I use:

  * **mod\_jail** is [Apache](http://httpd.apache.org/) module, that supports and 2.4.xx branche, it is very similar to [mod\_chroot](http://core.segfault.pl/~hobbit/mod_chroot/), but uses FreeBSD's specific system call - [jail](http://wikipedia.org/wiki/FreeBSD_jail) that is more secure than chroot, so, it is intended to run on FreeBSD only. Module has some drawbacks, for example, it breaks graceful restart, so there is also one _better_ way to run Apache in jail:
  * **jail patch** for Apache source code that is based on official chroot patch for Apache 2.2.10. I have combined both jail and chroot code in one patch, so it is possible to use this patch not only for FreeBSD, but for **Linux** too: if you build Apache on FreeBSD _jail_ syscall is used on other platforms _chroot_ is used. While official chroot code presents only in 2.2 branch (begining from 2.2.10), my patch includes chroot code for all Apache branches: 1.3, 2.0 and 2.2,. Using patch is preferred over module.


Default **mod\_jail** settings are:
```
<IfModule jail_module>
    jail_rootdir  "/"
    jail_hostname  "localhost"
    jail_address  127.0.0.1
    jail_address6  ::1
    jail_scrlevel  3
</IfModule>
```

### Copyright

  Copyright (c) 2006-2025 Igor Popov

License
-------
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

### Authors

  Igor Popov
  (ipopovi |at| gmail |dot| com)
