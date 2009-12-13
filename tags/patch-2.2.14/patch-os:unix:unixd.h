--- os/unix/unixd.h.orig	2008-09-18 21:42:18.000000000 +0300
+++ os/unix/unixd.h	2009-05-06 22:49:26.000000000 +0300
@@ -48,6 +48,21 @@
 #include <sys/ipc.h>
 #endif
 
+#ifndef __FreeBSD__
+#error "This patch for FreeBSD only!!!"
+#endif
+
+#include <osreldate.h>
+#if  !defined(__FreeBSD_version) || (__FreeBSD_version < 400000)
+#error "The jail() system call appeared in FreeBSD 4.0"
+#endif
+
+#include <sys/param.h>
+#include <sys/jail.h>
+#include <sys/sysctl.h>
+#include <netinet/in.h>
+#include <arpa/inet.h>
+
 typedef struct {
     uid_t uid;
     gid_t gid;
@@ -72,7 +87,8 @@
     uid_t user_id;
     gid_t group_id;
     int suexec_enabled;
-    const char *chroot_dir;
+    struct jail jail;
+    int jail_securelevel;
 } unixd_config_rec;
 AP_DECLARE_DATA extern unixd_config_rec unixd_config;
 
@@ -82,7 +98,13 @@
                                         const char *arg);
 AP_DECLARE(const char *) unixd_set_group(cmd_parms *cmd, void *dummy, 
                                          const char *arg);
-AP_DECLARE(const char *) unixd_set_chroot_dir(cmd_parms *cmd, void *dummy, 
+AP_DECLARE(const char *) unixd_set_jail_dir(cmd_parms *cmd, void *dummy, 
+                                              const char *arg);
+AP_DECLARE(const char *) unixd_set_jail_hostname(cmd_parms *cmd, void *dummy, 
+                                              const char *arg);
+AP_DECLARE(const char *) unixd_set_jail_address(cmd_parms *cmd, void *dummy, 
+                                              const char *arg);
+AP_DECLARE(const char *) unixd_set_jail_securelevel(cmd_parms *cmd, void *dummy, 
                                               const char *arg);
 					 
 #if defined(RLIMIT_CPU) || defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_NPROC) || defined(RLIMIT_AS)
@@ -116,8 +138,15 @@
   "Effective user id for this server"), \
 AP_INIT_TAKE1("Group", unixd_set_group, NULL, RSRC_CONF, \
   "Effective group id for this server"), \
-AP_INIT_TAKE1("ChrootDir", unixd_set_chroot_dir, NULL, RSRC_CONF, \
-    "The directory to chroot(2) into")
+AP_INIT_TAKE1("JailDir", unixd_set_jail_dir, NULL, RSRC_CONF, \
+    "The directory to jail(2) into"), \
+AP_INIT_TAKE1("JailHostname", unixd_set_jail_hostname, NULL, RSRC_CONF, \
+    "The hostname of jail prison"), \
+AP_INIT_TAKE1("JailAddress", unixd_set_jail_address, NULL, RSRC_CONF, \
+    "The IP address of jail prison"), \
+AP_INIT_TAKE1("JailSecureLevel", unixd_set_jail_securelevel, NULL, RSRC_CONF, \
+    "The securelevel inside jail prison")
+
 
 #endif
 /** @} */
