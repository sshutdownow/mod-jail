# Introduction #

Official port of **mod\_jail** version 0.4 have had a bug.

# Details #

So, if you install mod\_jail from ports for apache2 or apache22 and start **Apache**, you will see something like this:
```
httpd: Syntax error on line 114 of /usr/local/etc/apache22/httpd.conf: Cannot load /usr/local/libexec/apache22/mod_jail.so into server: 
/usr/local/libexec/apache22/mod_jail.so: Undefined symbol "ap_pcalloc"
```

[Error has appeared when support for the new jail API version two was added.](http://lists.freebsd.org/pipermail/freebsd-ports-bugs/2009-February/157933.html)

To **fix** that you should change ap\_pcalloc to apr\_pcalloc and rebuild module:
  * cd /usr/ports/www/mod\_jail
  * make config
  * perl -pi -e 's/ap\_pcalloc/apr\_pcalloc/g' work/mod\_jail/mod\_jail.c
  * make deinstall ; make all install