--- os/unix/unixd.h.orig	2008-09-18 21:42:18.000000000 +0300
+++ os/unix/unixd.h	2009-12-15 01:15:16.000000000 +0200
@@ -48,6 +48,27 @@
 #include <sys/ipc.h>
 #endif
 
+#if defined(__FreeBSD__)
+#include <osreldate.h>
+
+#if defined(__FreeBSD_version) && (__FreeBSD_version >= 400000)
+/* Jail(2) patch for FreeBSD */
+
+#include <sys/param.h>
+#include <sys/jail.h>
+#include <sys/sysctl.h>
+#include <netinet/in.h>
+#include <arpa/inet.h>
+
+#ifndef JAIL_API_VERSION
+#define JAIL_API_VERSION 0
+#endif
+
+#endif /* __FreeBSD_version */
+
+#endif /* __FreeBSD__ */
+
+
 typedef struct {
     uid_t uid;
     gid_t gid;
@@ -72,7 +93,12 @@
     uid_t user_id;
     gid_t group_id;
     int suexec_enabled;
+#if defined(JAIL_API_VERSION)
+    struct jail jail;
+    int jail_securelevel;
+#else /* chroot */
     const char *chroot_dir;
+#endif
 } unixd_config_rec;
 AP_DECLARE_DATA extern unixd_config_rec unixd_config;
 
@@ -82,8 +108,19 @@
                                         const char *arg);
 AP_DECLARE(const char *) unixd_set_group(cmd_parms *cmd, void *dummy, 
                                          const char *arg);
+#if defined(JAIL_API_VERSION)
+AP_DECLARE(const char *) unixd_set_jail_dir(cmd_parms *cmd, void *dummy, 
+                                              const char *arg);
+AP_DECLARE(const char *) unixd_set_jail_hostname(cmd_parms *cmd, void *dummy, 
+                                              const char *arg);
+AP_DECLARE(const char *) unixd_set_jail_address(cmd_parms *cmd, void *dummy, 
+                                              const char *arg);
+AP_DECLARE(const char *) unixd_set_jail_securelevel(cmd_parms *cmd, void *dummy, 
+                                              const char *arg);
+#else /* chroot */
 AP_DECLARE(const char *) unixd_set_chroot_dir(cmd_parms *cmd, void *dummy, 
                                               const char *arg);
+#endif /* JAIL_API_VERSION */
 					 
 #if defined(RLIMIT_CPU) || defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_NPROC) || defined(RLIMIT_AS)
 AP_DECLARE(void) unixd_set_rlimit(cmd_parms *cmd, struct rlimit **plimit,
@@ -111,6 +148,24 @@
 #define ap_os_killpg(x, y)      (kill (-(x), (y)))
 #endif /* HAVE_KILLPG */
 
+#if defined(JAIL_API_VERSION)
+
+#define UNIX_DAEMON_COMMANDS	\
+AP_INIT_TAKE1("User", unixd_set_user, NULL, RSRC_CONF, \
+  "Effective user id for this server"), \
+AP_INIT_TAKE1("Group", unixd_set_group, NULL, RSRC_CONF, \
+  "Effective group id for this server"), \
+AP_INIT_TAKE1("JailDir", unixd_set_jail_dir, NULL, RSRC_CONF, \
+    "The directory to jail(2) into"), \
+AP_INIT_TAKE1("JailHostname", unixd_set_jail_hostname, NULL, RSRC_CONF, \
+    "The hostname of jail prison"), \
+AP_INIT_TAKE1("JailAddress", unixd_set_jail_address, NULL, RSRC_CONF, \
+    "The IP address of jail prison"), \
+AP_INIT_TAKE1("JailSecureLevel", unixd_set_jail_securelevel, NULL, RSRC_CONF, \
+    "The securelevel inside jail prison")
+
+#else /* chroot */
+
 #define UNIX_DAEMON_COMMANDS	\
 AP_INIT_TAKE1("User", unixd_set_user, NULL, RSRC_CONF, \
   "Effective user id for this server"), \
@@ -119,5 +174,7 @@
 AP_INIT_TAKE1("ChrootDir", unixd_set_chroot_dir, NULL, RSRC_CONF, \
     "The directory to chroot(2) into")
 
+#endif /* JAIL_API_VERSION */
+
 #endif
 /** @} */
