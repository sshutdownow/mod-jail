--- os/unix/unixd.h.orig	2006-07-12 10:40:55.000000000 +0300
+++ os/unix/unixd.h	2009-09-04 23:34:19.000000000 +0300
@@ -40,6 +40,26 @@
 #include <sys/ipc.h>
 #endif
 
+#if defined(__FreeBSD__)
+#include <osreldate.h>
+
+#if defined(__FreeBSD_version) && (__FreeBSD_version >= 400000)
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
@@ -65,6 +85,12 @@
     uid_t user_id;
     gid_t group_id;
     int suexec_enabled;
+#if defined(JAIL_API_VERSION)
+    struct jail jail;
+    int jail_securelevel;
+#else
+    const char *chroot_dir;
+#endif
 } unixd_config_rec;
 AP_DECLARE_DATA extern unixd_config_rec unixd_config;
 
@@ -74,6 +100,19 @@
                                         const char *arg);
 AP_DECLARE(const char *) unixd_set_group(cmd_parms *cmd, void *dummy, 
                                          const char *arg);
+#if defined(JAIL_API_VERSION)
+AP_DECLARE(const char *) unixd_set_jail_dir(cmd_parms *cmd, void *dummy, 
+					    const char *arg);
+AP_DECLARE(const char *) unixd_set_jail_hostname(cmd_parms *cmd, void *dummy, 
+					    const char *arg);
+AP_DECLARE(const char *) unixd_set_jail_address(cmd_parms *cmd, void *dummy, 
+					    const char *arg);
+AP_DECLARE(const char *) unixd_set_jail_securelevel(cmd_parms *cmd, void *dummy, 
+					    const char *arg);
+#else /* chroot */
+AP_DECLARE(const char *) unixd_set_chroot_dir(cmd_parms *cmd, void *dummy,
+					    const char *arg);
+#endif /* JAIL_API_VERSION */
 #if defined(RLIMIT_CPU) || defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_NPROC) || defined(RLIMIT_AS)
 AP_DECLARE(void) unixd_set_rlimit(cmd_parms *cmd, struct rlimit **plimit,
                            const char *arg, const char * arg2, int type);
@@ -100,10 +139,33 @@
 #define ap_os_killpg(x, y)      (kill (-(x), (y)))
 #endif /* HAVE_KILLPG */
 
+
+#if defined(JAIL_API_VERSION)
+
 #define UNIX_DAEMON_COMMANDS	\
 AP_INIT_TAKE1("User", unixd_set_user, NULL, RSRC_CONF, \
   "Effective user id for this server"), \
 AP_INIT_TAKE1("Group", unixd_set_group, NULL, RSRC_CONF, \
-  "Effective group id for this server")
+  "Effective group id for this server"), \
+AP_INIT_TAKE1("JailDir", unixd_set_jail_dir, NULL, RSRC_CONF, \
+  "The directory to jail(2) into"), \
+AP_INIT_TAKE1("JailHostname", unixd_set_jail_hostname, NULL, RSRC_CONF, \
+  "The hostname of jail prison"), \
+AP_INIT_TAKE1("JailAddress", unixd_set_jail_address, NULL, RSRC_CONF, \
+  "The IP address of jail prison"), \
+AP_INIT_TAKE1("JailSecureLevel", unixd_set_jail_securelevel, NULL, RSRC_CONF, \
+  "The securelevel inside jail prison")
+
+#else /* chroot */
+
+#define UNIX_DAEMON_COMMANDS	\
+AP_INIT_TAKE1("User", unixd_set_user, NULL, RSRC_CONF, \
+  "Effective user id for this server"), \
+AP_INIT_TAKE1("Group", unixd_set_group, NULL, RSRC_CONF, \
+  "Effective group id for this server"), \
+AP_INIT_TAKE1("ChrootDir", unixd_set_chroot_dir, NULL, RSRC_CONF, \
+  "The directory to chroot(2) into")
+
+#endif /* JAIL_API_VERSION */
 
 #endif
