--- server/core.c.orig	2009-12-15 01:24:09.000000000 +0200
+++ server/core.c	2009-12-15 01:23:57.000000000 +0200
@@ -1212,7 +1212,11 @@
     /* TODO: ap_configtestonly && ap_docrootcheck && */
     if (apr_filepath_merge((char**)&conf->ap_document_root, NULL, arg,
                            APR_FILEPATH_TRUENAME, cmd->pool) != APR_SUCCESS
-        || !ap_is_directory(cmd->pool, arg)) {
+#if defined(JAIL_API_VERSION)
+        || !ap_is_directory(cmd->pool, (unixd_config.jail.path != NULL? apr_pstrcat(cmd->pool, unixd_config.jail.path, "/", arg, NULL) : arg)) ) {
+#else /* chroot */
+        || !ap_is_directory(cmd->pool, (unixd_config.chroot_dir != NULL? apr_pstrcat(cmd->pool, unixd_config.chroot_dir, "/", arg, NULL) : arg)) ) {
+#endif
         if (cmd->server->is_virtual) {
             ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0,
                           cmd->pool,
