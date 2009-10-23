/*
 * Copyright (c) 2006-2009 Igor Popov <ipopovi@gmail.com>
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
 */


#ifndef __FreeBSD__
#error "This module only for FreeBSD"
#endif

#include <osreldate.h>
#if  !defined(__FreeBSD_version) || (__FreeBSD_version < 400000)
#error "The jail() system call appeared in FreeBSD 4.0"
#endif

#define CORE_PRIVATE

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_core.h"
#include "http_log.h"
#include "apr.h"
#include "apr_pools.h"
#include "apr_strings.h"

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#if !defined(JAIL_API_VERSION)
#define JAIL_API_VERSION 0
#endif

#define JAIL_CTX "global::jail_module_ctx"

static const char __unused cvsid[] = "$Id$";

typedef struct {
    struct jail jail;
    int    jail_scrlevel;
} jail_cfg_t, *p_jail_cfg_t;

typedef struct {
    int	   is_jailed;
} jail_ctx_t, *p_jail_ctx_t;



module AP_MODULE_DECLARE_DATA jail_module;

static int jail_init(apr_pool_t *p __unused, apr_pool_t *plog __unused, apr_pool_t *ptemp, server_rec *s)
{
    p_jail_cfg_t cfg = (p_jail_cfg_t)ap_get_module_config(s->module_config, &jail_module);
    p_jail_ctx_t jail_ctx;

    if (!cfg->jail.path) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, s,
                     "mod_jail jail's root directory is not defined");
        return !OK;
    }
    if (!ap_is_directory(ptemp, cfg->jail.path)) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, s,
                     "mod_jail jail's root directory doesn't exist.");
        return !OK;
    }
    if (!cfg->jail.hostname) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, s,
                     "mod_jail jail's hostname is not defined.");
        return !OK;
    }

    apr_pool_userdata_get((void**)&jail_ctx, JAIL_CTX, s->process->pool);

    if (jail_ctx == NULL) {
        jail_ctx = (p_jail_ctx_t)apr_palloc(s->process->pool, sizeof(jail_ctx_t));
        jail_ctx->is_jailed = 0;
        apr_pool_userdata_set(jail_ctx, JAIL_CTX, apr_pool_cleanup_null, s->process->pool);
    } else if (jail_ctx->is_jailed++ == 0) {
	if (geteuid()) {
	    ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s,
			"mod_jail can't jail when not started as root.");
	    return;
	}
	if (chdir(cfg->jail.path) == -1) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
    		     "mod_jail unable to chdir to %s.", cfg->jail.path);
    	    return;
	}
        if (jail(&cfg->jail) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "mod_jail call jail() failed.");
            return !OK;
        }
        if (chdir("/") == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "mod_jail call chdir() failed.");
            return !OK;
        }
        if (cfg->jail_scrlevel > 0) {
#if 1
            if (sysctl((int[]){ CTL_KERN, KERN_SECURELVL }, 2, 0, 0,
        		&cfg->jail_scrlevel, sizeof(cfg->jail_scrlevel)) == -1) {
#else
	    if (sysctlbyname("kern.securelevel", 0, 0,
			&cfg->jail_scrlevel, sizeof(cfg->jail_scrlevel)) == -1) {
#endif
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "mod_jail call sysctl() to set up kern.securelevel failed.");
                return !OK;
            }
        }
    }

    return OK;
}

static void *jail_server_config(apr_pool_t *p, server_rec *s __unused)
{
    p_jail_cfg_t cfg = (p_jail_cfg_t) apr_pcalloc(p, sizeof(jail_cfg_t));
    struct in_addr *p_addr = NULL;

    if (cfg == NULL) {
        return NULL;
    }

#if JAIL_API_VERSION == 0
    cfg->jail = (struct jail) {
	.version = JAIL_API_VERSION,
	.path = NULL,
	.hostname = "localhost",
	.ip_number = INADDR_LOOPBACK };
#elif JAIL_API_VERSION == 2
    p_addr = apr_pcalloc(p, sizeof(struct in_addr));
    if (p_addr == NULL) {
        return NULL;
    }
    addr->s_addr = htonl(INADDR_LOOPBACK);
    cfg->jail = (struct jail) {
	.version = JAIL_API_VERSION,
	.path = NULL,
	.hostname = "localhost",
	.jailname = NULL,
	.ip4s = 1,
	.ip6s = 0,
	.ip4 = p_addr,
	.ip6 = NULL };
#endif
    cfg->jail_scrlevel = 3; /* good default value */

    return (void*)cfg;
}


/* Config stuff */
static const char *set_jail_root(cmd_parms *cmd, void *dummy __unused, const char *arg)
{
    p_jail_cfg_t cfg = ap_get_module_config(cmd->server->module_config, &jail_module);
    const char *errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (errmsg) {
        return errmsg;
    }
    if (!arg || !strlen(arg)) {
        return "jail_rootdir must be set";
    }
    if (!ap_is_directory(cmd->pool, arg)) {
        return "jail_rootdir doesn't exist";
    }

    cfg->jail.path = arg;

    return NULL;
}

static const char *set_jail_host(cmd_parms *cmd, void *dummy __unused, const char *arg)
{
    p_jail_cfg_t cfg = ap_get_module_config(cmd->server->module_config, &jail_module);
    const char *errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (errmsg) {
        return errmsg;
    }
    if (!arg || !strlen(arg)) {
        return "jail_hostname must be set";
    }

    cfg->jail.hostname = arg;

    return NULL;
}

static const char *set_jail_addr(cmd_parms *cmd, void *dummy __unused, const char *arg)
{
    p_jail_cfg_t cfg = ap_get_module_config(cmd->server->module_config, &jail_module);
    struct in_addr in;
    const char *errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (errmsg) {
        return errmsg;
    }
    if (!arg || !strlen(arg)) {
        return "jail_address must be set";
    }
    if (!inet_aton(arg, &in)) {
        return "could not make sense of jail ip address";
    }
#if JAIL_API_VERSION == 0
    cfg->jail.ip_number = ntohl(in.s_addr);
#elif JAIL_API_VERSION == 2
    cfg->jail.ip4[0].s_addr = in.s_addr;
#endif

    return NULL;
}

static const char *set_jail_scrlvl(cmd_parms *cmd, void *dummy __unused, const char *arg)
{
    p_jail_cfg_t cfg = ap_get_module_config(cmd->server->module_config, &jail_module);
    const char *errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (errmsg) {
        return errmsg;
    }
    if (!arg || !strlen(arg)) {
        return "jail_scrlevel must be value from set {-1, 0, 1, 2, 3}";
    }
    cfg->jail_scrlevel = strtol(arg, 0, 10) & 0x03;

    return NULL;
}

/* Dispatch list of content handlers */
static const command_rec jail_cmds[] = {
    AP_INIT_TAKE1("jail_rootdir",  set_jail_root, NULL, RSRC_CONF, "Set directory that is to be the root of the prison."),
    AP_INIT_TAKE1("jail_hostname", set_jail_host, NULL, RSRC_CONF, "Set hostname of the prison."),
    AP_INIT_TAKE1("jail_address",  set_jail_addr, NULL, RSRC_CONF, "Set the ip address assigned to the jail prison."),
    AP_INIT_TAKE1("jail_scrlevel", set_jail_scrlvl, NULL, RSRC_CONF, "Set securelevel inside jail prison."),
    { NULL },
};

static void register_hooks(apr_pool_t *pool __unused)
{
    static const char* const init_after[] = { "mod_fcgid.c", "mod_cgid.c", NULL };
    ap_hook_post_config(jail_init, init_after, NULL, APR_HOOK_REALLY_LAST);
}


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA jail_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    jail_server_config,    /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    jail_cmds,             /* table of config file commands       */
    register_hooks         /* register hooks                      */
};
