--- os/unix/unixd.c.orig	2008-09-18 21:42:18.000000000 +0300
+++ os/unix/unixd.c	2009-03-13 22:48:40.000000000 +0200
@@ -118,20 +118,20 @@
         return -1;
     }
 
-    if (NULL != unixd_config.chroot_dir) {
+    if (NULL != unixd_config.jail.path) {
         if (geteuid()) {
             ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
-                         "Cannot chroot when not started as root");
+                         "Cannot jail when not started as root");
             return -1;
         }
-        if (chdir(unixd_config.chroot_dir) != 0) {
+        if (chdir(unixd_config.jail.path) != 0) {
             ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
-                         "Can't chdir to %s", unixd_config.chroot_dir);
+                         "Can't chdir to %s", unixd_config.jail.path);
             return -1;
         }
-        if (chroot(unixd_config.chroot_dir) != 0) {
+        if (jail(&unixd_config.jail) == -1) {
             ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
-                         "Can't chroot to %s", unixd_config.chroot_dir);
+                         "Can't jail to %s", unixd_config.jail.path);
             return -1;
         }
         if (chdir("/") != 0) {
@@ -139,6 +139,13 @@
                          "Can't chdir to new root");
             return -1;
         }
+        if (unixd_config.jail_securelevel > 0) {
+    	    if (sysctl((int[]){ CTL_KERN, KERN_SECURELVL }, 2, 0, 0,
+    		    &unixd_config.jail_securelevel, sizeof(unixd_config.jail_securelevel)) != 0)
+    		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
+    		             "Can't set kern.securelevel via sysctl()");
+    		                         
+        }
     }
 
 #ifdef MPE
@@ -222,7 +229,7 @@
 
     return NULL;
 }
-AP_DECLARE(const char *) unixd_set_chroot_dir(cmd_parms *cmd, void *dummy,
+AP_DECLARE(const char *) unixd_set_jail_dir(cmd_parms *cmd, void *dummy,
                                               const char *arg)
 {
     const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
@@ -230,10 +237,51 @@
         return err;
     }
     if (!ap_is_directory(cmd->pool, arg)) {
-        return "ChrootDir must be a valid directory";
+        return "JailDir must be a valid directory";
     }
 
-    unixd_config.chroot_dir = arg;
+    unixd_config.jail.path = arg;
+    return NULL;
+}
+AP_DECLARE(const char *) unixd_set_jail_hostname(cmd_parms *cmd, void *dummy,
+                                              const char *arg)
+{
+    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
+    if (err != NULL) {
+        return err;
+    }
+
+    unixd_config.jail.hostname = arg;
+    return NULL;
+}
+AP_DECLARE(const char *) unixd_set_jail_address(cmd_parms *cmd, void *dummy,
+                                              const char *arg)
+{
+    struct in_addr in;
+    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
+    if (err != NULL) {
+        return err;
+    }
+    if (!inet_aton(arg, &in)) {
+	return "could not make sense of jail ip address";
+    }
+
+#if ((__FreeBSD_version >= 800000 && __FreeBSD_version < 800056) || __FreeBSD_version < 701103)
+    unixd_config.jail.ip_number = ntohl(in.s_addr);
+#else
+    unixd_config.jail.ip4[0].s_addr = in.s_addr;
+#endif
+    return NULL;
+}
+AP_DECLARE(const char *) unixd_set_jail_securelevel(cmd_parms *cmd, void *dummy,
+                                              const char *arg)
+{
+    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
+    if (err != NULL) {
+        return err;
+    }
+
+    unixd_config.jail_securelevel = strtol(arg, 0, 10) & 0x03;
     return NULL;
 }
 
@@ -245,7 +293,19 @@
     unixd_config.user_id = ap_uname2id(DEFAULT_USER);
     unixd_config.group_id = ap_gname2id(DEFAULT_GROUP);
     
-    unixd_config.chroot_dir = NULL; /* none */
+    memset(&unixd_config.jail, 0, sizeof(unixd_config.jail));
+    unixd_config.jail.path = NULL; /* none */
+    unixd_config.jail.hostname = "localhost";
+#if ((__FreeBSD_version >= 800000 && __FreeBSD_version < 800056) || __FreeBSD_version < 701103)
+    unixd_config.jail.version = 0;
+    unixd_config.jail.ip_number = INADDR_LOOPBACK;
+#else
+    unixd_config.jail.version = JAIL_API_VERSION;
+    unixd_config.jail.ip4s = 1;
+    unixd_config.jail.ip4 = ap_pcalloc(cmd->pool, sizeof(struct in_addr));
+    unixd_config.jail.ip4[0].s_addr = htonl(INADDR_LOOPBACK);
+#endif
+    unixd_config.jail_securelevel = 3;
 
     /* Check for suexec */
     unixd_config.suexec_enabled = 0;
