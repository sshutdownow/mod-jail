--- os/unix/unixd.c.orig	2006-07-12 10:40:55.000000000 +0300
+++ os/unix/unixd.c	2009-09-04 23:52:39.000000000 +0300
@@ -117,6 +117,60 @@
     if (set_group_privs()) {
 	return -1;
     }
+#if defined(JAIL_API_VERSION)
+    if (NULL != unixd_config.jail.path) {
+        if (geteuid()) {
+            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
+                         "Cannot jail when not started as root");
+            return -1;
+        }
+        if (chdir(unixd_config.jail.path) != 0) {
+            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
+                         "Can't chdir to %s", unixd_config.jail.path);
+            return -1;
+        }
+        if (jail(&unixd_config.jail) == -1) {
+            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
+                         "Can't jail to %s", unixd_config.jail.path);
+            return -1;
+        }
+        if (chdir("/") != 0) {
+            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
+                         "Can't chdir to new root");
+            return -1;
+        }
+        if (unixd_config.jail_securelevel > 0) {
+    	    if (sysctl((int[]){ CTL_KERN, KERN_SECURELVL }, 2, 0, 0,
+    		    &unixd_config.jail_securelevel, sizeof(unixd_config.jail_securelevel)) != 0)
+    		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
+    		             "Can't set kern.securelevel via sysctl()");
+        }
+    }
+#else /* chroot */
+    if (NULL != unixd_config.chroot_dir) {
+        if (geteuid()) {
+            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
+                         "Cannot chroot when not started as root");
+            return -1;
+        }
+        if (chdir(unixd_config.chroot_dir) != 0) {
+            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
+                         "Can't chdir to %s", unixd_config.chroot_dir);
+            return -1;
+        }
+        if (chroot(unixd_config.chroot_dir) != 0) {
+            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
+                         "Can't chroot to %s", unixd_config.chroot_dir);
+            return -1;
+        }
+        if (chdir("/") != 0) {
+            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
+                         "Can't chdir to new root");
+            return -1;
+        }
+    }
+#endif /* JAIL_API_VERSION */
+
 #ifdef MPE
     /* Only try to switch if we're running as MANAGER.SYS */
     if (geteuid() == 1 && unixd_config.user_id > 1) {
@@ -198,7 +252,78 @@
 
     return NULL;
 }
+#if defined(JAIL_API_VERSION)
+AP_DECLARE(const char *) unixd_set_jail_dir(cmd_parms *cmd, void *dummy,
+                                              const char *arg)
+{
+    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
+    if (err != NULL) {
+        return err;
+    }
+    if (!ap_is_directory(cmd->pool, arg)) {
+        return "JailDir must be a valid directory";
+    }
+
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
+#if JAIL_API_VERSION == 2
+    unixd_config.jail.ip4[0].s_addr = in.s_addr;
+#else /* JAIL_API_VERSION == 0 */
+    unixd_config.jail.ip_number = ntohl(in.s_addr);
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
+    return NULL;
+}
+#else /* chroot */
+AP_DECLARE(const char *) unixd_set_chroot_dir(cmd_parms *cmd, void *dummy,
+                                              const char *arg)
+{
+    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
+    if (err != NULL) {
+        return err;
+    }
+    if (!ap_is_directory(cmd->pool, arg)) {
+        return "ChrootDir must be a valid directory";
+    }
 
+    unixd_config.chroot_dir = arg;
+    return NULL;
+}
+#endif /* JAIL_API_VERSION */
 AP_DECLARE(void) unixd_pre_config(apr_pool_t *ptemp)
 {
     apr_finfo_t wrapper;
@@ -207,6 +332,25 @@
     unixd_config.user_id = ap_uname2id(DEFAULT_USER);
     unixd_config.group_id = ap_gname2id(DEFAULT_GROUP);
 
+#if defined(JAIL_API_VERSION)
+#if JAIL_API_VERSION == 2
+    unixd_config.jail.version = JAIL_API_VERSION;
+    unixd_config.jail.path = NULL; /* none */
+    unixd_config.jail.hostname = "localhost";
+    unixd_config.jail.jailname = NULL;
+    unixd_config.jail.ip4s = 1;
+    unixd_config.jail.ip6s = 0;
+    unixd_config.jail.ip4 = apr_pcalloc(ptemp, sizeof(struct in_addr));
+    unixd_config.jail.ip4[0].s_addr = htonl(INADDR_LOOPBACK);
+    unixd_config.jail.ip6 = NULL;
+#else /* JAIL_API_VERSION == 0 */
+    unixd_config.jail = { .version = 0, .path = NULL, .hostname = "localhost", .ip_number = INADDR_LOOPBACK };
+#endif
+    unixd_config.jail_securelevel = 3;
+#else /* chroot */
+    unixd_config.chroot_dir = NULL; /* none */
+#endif /* JAIL_API_VERSION */
+
     /* Check for suexec */
     unixd_config.suexec_enabled = 0;
     if ((apr_stat(&wrapper, SUEXEC_BIN, 