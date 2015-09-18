/*	$OpenBSD: login_krb5.c,v 1.27 2013/06/21 13:35:26 ajacoutot Exp $	*/

/*-
 * Copyright (c) 2001, 2002 Hans Insulander <hin@openbsd.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "common.h"

#include <krb5.h>

krb5_error_code ret;
krb5_context context;
krb5_ccache ccache;
krb5_principal princ;

char *__progname;

static void
krb5_syslog(krb5_context context, int level, krb5_error_code code, char *fmt, ...)
{
	va_list ap;
	char buf[256];
	const char *s = krb5_get_error_message(context, code);

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	syslog(level, "%s: %s", buf, s);
	krb5_free_error_message(context, s);
}

static void
store_tickets(struct passwd *pwd, int ticket_newfiles, int ticket_store,
    int token_install)
{
	char cc_file[PATH_MAX];
	krb5_ccache ccache_store;

	if (ticket_newfiles)
		snprintf(cc_file, sizeof(cc_file), "FILE:/tmp/krb5cc_%d",
		    pwd->pw_uid);
	else
		snprintf(cc_file, sizeof(cc_file), "%s",
		    krb5_cc_default_name(context));

	if (ticket_store) {
		ret = krb5_cc_resolve(context, cc_file, &ccache_store);
		if (ret != 0) {
			krb5_syslog(context, LOG_ERR, ret,
			    "krb5_cc_resolve");
			exit(1);
		}

		ret = krb5_cc_copy_cache(context, ccache, ccache_store);
		if (ret != 0)
			krb5_syslog(context, LOG_ERR, ret,
			    "krb5_cc_copy_cache");

		chown(krb5_cc_get_name(context, ccache_store),
		    pwd->pw_uid, pwd->pw_gid);

		fprintf(back, BI_SETENV " KRB5CCNAME %s:%s\n",
		    krb5_cc_get_type(context, ccache_store),
		    krb5_cc_get_name(context, ccache_store));
	}
}

int
krb5_login(char *username, char *invokinguser, char *password, int login,
    int tickets, char *class)
{
	login_cap_t *lc;
	int return_code = AUTH_FAILED;
	int noverify = 0;

	if (username == NULL || password == NULL)
		return (AUTH_FAILED);

	if (strcmp(__progname, "krb5-or-pwd") == 0 &&
	    strcmp(username,"root") == 0 && invokinguser[0] == '\0')
		return (AUTH_FAILED);

	lc = login_getclass(class);
	if (lc != NULL)
		noverify = login_getcapbool(lc, "krb5-noverify", noverify);

	ret = krb5_init_context(&context);
	if (ret != 0) {
		krb5_syslog(context, LOG_ERR, ret, "krb5_init_context");
		exit(1);
	}

	ret = krb5_cc_new_unique(context, krb5_mcc_ops.prefix, NULL, &ccache);
	if (ret != 0) {
		krb5_syslog(context, LOG_ERR, ret, "krb5_cc_new_unique");
		exit(1);
	}

	if (strcmp(username, "root") == 0 && invokinguser[0] != '\0') {
		char *tmp;

		ret = asprintf(&tmp, "%s/root", invokinguser);
		if (ret == -1) {
			krb5_syslog(context, LOG_ERR, ret, "asprintf");
			exit(1);
		}
		ret = krb5_parse_name(context, tmp, &princ);
		free(tmp);
	} else
		ret = krb5_parse_name(context, username, &princ);
	if (ret != 0) {
		krb5_syslog(context, LOG_ERR, ret, "krb5_parse_name");
		exit(1);
	}

	ret = krb5_verify_user_lrealm(context, princ, ccache,
	    password, !noverify, NULL);

	switch (ret) {
	case 0: {
		struct passwd *pwd;

		pwd = getpwnam(username);
		if (pwd == NULL) {
			krb5_syslog(context, LOG_ERR, ret,
			    "%s: no such user", username);
			return (AUTH_FAILED);
		}
		fprintf(back, BI_AUTH "\n");
		store_tickets(pwd, login && tickets, login && tickets, login);
		return_code = AUTH_OK;
		break;
	}
	case KRB5KRB_AP_ERR_MODIFIED:
		/* XXX syslog here? */
	case KRB5KRB_AP_ERR_BAD_INTEGRITY:
		break;
	default:
		krb5_syslog(context, LOG_ERR, ret, "verify");
		break;
	}

	krb5_free_principal(context, princ);
	krb5_cc_close(context, ccache);
	krb5_free_context(context);

	return (return_code);
}
