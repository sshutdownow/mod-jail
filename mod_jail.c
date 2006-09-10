/*
 * Copyright (c) 2006 Igor Popov <igorpopov@newmail.ru>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * $Author$
 * $Date$
 */
	      
#ifndef __FreeBSD__
#error "This module only for FreeBSD"
#endif

static const char cvsid[] = "$Revision$";
	      
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_conf_globals.h"
#include "ap_config.h"
#include "util_script.h"

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>


module MODULE_VAR_EXPORT jail_module;

typedef struct {
    struct jail jail;
    int    jail_scrlevel;
} jail_cfg_t, *p_jail_cfg_t;


/* init() occurs after config parsing, but before any children are forked. */
static void jail_init(server_rec *s, pool *p)
{
    jail_cfg_t *cfg = ap_get_module_config(s->module_config, &jail_module);
    static int mib[] = { CTL_KERN, KERN_SECURELVL };

    if (!cfg->jail.path ||
	!ap_is_directory(cfg->jail.path) ||
	!cfg->jail.hostname)
    {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, s,
	    "mod_jail is not properly configured.");
	return;
    } 
    
    if (getenv("MOD_JAIL_INITIALIZED")) {
	unsetenv("MOD_JAIL_INITIALIZED");

	if (jail(&cfg->jail) == -1) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, s, "mod_jail call jail() failed.");
	}

	if (chdir("/") == -1) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, s, "mod_jail call chdir() failed.");
	}

	if (sysctl(mib, sizeof(mib)/sizeof(mib[0]), 0, 0, &cfg->jail_scrlevel, sizeof(cfg->jail_scrlevel)) == -1) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, s, "mod_jail call sysctl() to set up kern.securelevel failed.");
	}

    } else {
	setenv("MOD_JAIL_INITIALIZED", "", 0);
    }

    return;
}

static void *jail_server_config(pool *p, server_rec *s)
{
    jail_cfg_t *cfg = (jail_cfg_t *) ap_pcalloc(p, sizeof(jail_cfg_t));
    cfg->jail.version = 0;
    return (void *)cfg;
}
	

/* Config stuff */

static const char *set_jail_root(cmd_parms *cmd, void *__unused__, char *arg)
{
    jail_cfg_t *cfg = ap_get_module_config(cmd->server->module_config, &jail_module);
    if (!arg || !strlen(arg)) {
        return "jail_rootdir must be set";
    }

    if (!ap_is_directory(arg)) {
        return "jail_rootdir must be existing directory";
    }	

    cfg->jail.path = ap_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *set_jail_host(cmd_parms *cmd, void *__unused__, char *arg)
{
    jail_cfg_t *cfg = ap_get_module_config(cmd->server->module_config, &jail_module);
    if (!arg || !strlen(arg)) {
        return "jail_hostname must be set";
    }
    cfg->jail.hostname = ap_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *set_jail_addr(cmd_parms *cmd, void *__unused__, char *arg)
{
    jail_cfg_t *cfg;
    struct in_addr in;
    
    if (!arg || !strlen(arg)) {
        return "jail_address must be set";
    }
    if (!inet_aton(arg, &in)) {
	return "could not make sense of jail ip address";
    }

    cfg = ap_get_module_config(cmd->server->module_config, &jail_module);
    cfg->jail.ip_number = ntohl(in.s_addr);

    return NULL;
}

static const char *set_jail_scrlvl(cmd_parms *cmd, void *__unused__, char *arg)
{
    jail_cfg_t *cfg = ap_get_module_config(cmd->server->module_config, &jail_module);
    if (!arg || !strlen(arg)) {
        return "jail_scrlevel must be set to value one from {-1, 0, 1, 2, 3}";
    }	
    cfg->jail_scrlevel = ap_strtol(arg, 0, 10) & 0x03;
    return NULL;
}

/* Dispatch list of content handlers */
static const command_rec jail_cmds[] = { 
    { "jail_rootdir", set_jail_root, NULL, RSRC_CONF, TAKE1, "Set directory which is to be the root of the prison."},
    { "jail_hostname", set_jail_host, NULL, RSRC_CONF, TAKE1, "Set hostname of the prison."},
    { "jail_address", set_jail_addr, NULL, RSRC_CONF, TAKE1, "Set the ip address assigned to the jail prison."},
    { "jail_scrlevel", set_jail_scrlvl, NULL, RSRC_CONF, TAKE1, "Set securelevel inside jail prison."},
    { NULL, NULL }
};

/* Dispatch list for API hooks */
module MODULE_VAR_EXPORT jail_module = {
    STANDARD_MODULE_STUFF, 
    jail_init,             /* module initializer                  */
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    jail_server_config,    /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    jail_cmds,             /* table of config file commands       */
    NULL,                  /* [#8] MIME-typed-dispatched handlers */
    NULL,                  /* [#1] URI to filename translation    */
    NULL,                  /* [#4] validate user id from request  */
    NULL,                  /* [#5] check if the user is ok _here_ */
    NULL,                  /* [#3] check access by host address   */
    NULL,                  /* [#6] determine MIME type            */
    NULL,                  /* [#7] pre-run fixups                 */
    NULL,                  /* [#9] log a transaction              */
    NULL,                  /* [#2] header parser                  */
    NULL,                  /* child_init                          */
    NULL,                  /* child_exit                          */
    NULL,                  /* [#0] post read-request              */
#ifdef EAPI
    NULL,                  /* EAPI: add_module */
    NULL,                  /* EAPI: remove_module */
    NULL,                  /* EAPI: rewrite_command */
    NULL,                  /* EAPI: new_connection */
#endif
};
