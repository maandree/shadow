/*
 * Copyright (c) 1997 - 1999, Marek Michałkiewicz
 * Copyright (c) 2001 - 2005, Tomasz Kłoczko
 * Copyright (c) 2008       , Nicolas François
 * Copyright (c) 2015       , Mattias Andrée
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
 * 3. The name of the copyright holders or contributors may not be used to
 *    endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>

#ifdef USE_PAM

#ident "$Id$"


/*
 * Change the user's password using PAM.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include "defines.h"
#include "pam_defs.h"
#include "prototypes.h"
#include "xgetpass.h"

static int xgetpass_conv (int num_msg, const struct pam_message **msg,
			  struct pam_response **resp, void *appdata_ptr)
{
	struct pam_response *response;
	static int first_enter = 0;
	int current;
	int saved_errno;

	if ((num_msg != 1) || (msg[0]->msg_style != PAM_PROMPT_ECHO_OFF))
		return conv.conv (num_msg, msg, resp, appdata_ptr);

	response = calloc((size_t)1, sizeof(struct pam_response));
	if (response == NULL) {
		return PAM_CONV_ERR;
	}

	current = strchr(msg[0]->msg, '(') != NULL;
	first_enter ^= !current;
	response->resp_retcode = 0;
	response->resp = xgetpass (msg[0]->msg, first_enter & !current);
	if (response->resp == NULL) {
		saved_errno = errno;
		free(response);
		errno = saved_errno;
		return PAM_CONV_ERR;
	}

	*resp = response;
	return PAM_SUCCESS;
}


void do_pam_passwd (const char *user, bool silent, bool change_expired)
{
	pam_handle_t *pamh = NULL;
	int flags = 0, ret;
	struct pam_conv conv_proper = conv;

	conv_proper.conv = xgetpass_conv;

	if (silent)
		flags |= PAM_SILENT;
	if (change_expired)
		flags |= PAM_CHANGE_EXPIRED_AUTHTOK;

	ret = pam_start ("passwd", user, &conv_proper, &pamh);
	if (ret != PAM_SUCCESS) {
		fprintf (stderr,
			 _("passwd: pam_start() failed, error %d\n"), ret);
		exit (10);	/* XXX */
	}

	ret = pam_chauthtok (pamh, flags);
	if (ret != PAM_SUCCESS) {
		fprintf (stderr, _("passwd: %s\n"), pam_strerror (pamh, ret));
		fputs (_("passwd: password unchanged\n"), stderr);
		pam_end (pamh, ret);
		exit (10);	/* XXX */
	}

	fputs (_("passwd: password updated successfully\n"), stderr);
	(void) pam_end (pamh, PAM_SUCCESS);
}
#else				/* !USE_PAM */
extern int errno;		/* warning: ANSI C forbids an empty source file */
#endif				/* !USE_PAM */
