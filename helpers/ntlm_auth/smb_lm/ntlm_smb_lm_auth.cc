/*
 * (C) 2000 Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it>
 * Distributed freely under the terms of the GNU General Public License,
 * version 2. See the file COPYING for licensing details
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#include "squid.h"
#include "base64.h"
#include "compat/debug.h"
#include "ntlmauth/ntlmauth.h"
#include "ntlmauth/support_bits.cci"
#include "rfcnb/rfcnb.h"
#include "smblib/smblib.h"
//#include "util.h"

#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif


/************* CONFIGURATION ***************/

#define DEAD_DC_RETRY_INTERVAL 30

/************* END CONFIGURATION ***************/

/* A couple of harmless helper macros */
#define SEND(X) debug("sending '%s' to squid\n",X); printf(X "\n");
#ifdef __GNUC__
#define SEND2(X,Y...) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#define SEND3(X,Y...) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#else
/* no gcc, no debugging. varargs macros are a gcc extension */
#define SEND2 printf
#define SEND3 printf
#endif

const char *make_challenge(char *domain, char *controller);
char *ntlm_check_auth(ntlm_authenticate * auth, int auth_length);
void dc_disconnect(void);
int connectedp(void);
int is_dc_ok(char *domain, char *domain_controller);

typedef struct _dc dc;
struct _dc {
    char *domain;
    char *controller;
    time_t dead;		/* 0 if it's alive, otherwise time of death */
    dc *next;
};

/* local functions */
void send_bh_or_ld(char const *bhmessage, ntlm_authenticate * failedauth, int authlen);
void usage(void);
void process_options(int argc, char *argv[]);
const char * obtain_challenge(void);
void manage_request(void);


#define ENCODED_PASS_LEN 24
#define MAX_USERNAME_LEN 255
#define MAX_DOMAIN_LEN 255
#define MAX_PASSWD_LEN 31

static unsigned char challenge[NTLM_NONCE_LEN];
static unsigned char lmencoded_empty_pass[ENCODED_PASS_LEN],
ntencoded_empty_pass[ENCODED_PASS_LEN];
SMB_Handle_Type handle = NULL;
int ntlm_errno;
static char credentials[MAX_USERNAME_LEN+MAX_DOMAIN_LEN+2];	/* we can afford to waste */
static char my_domain[100], my_domain_controller[100];
static char errstr[1001];
#if DEBUG
char error_messages_buffer[NTLM_BLOB_BUFFER_SIZE];
#endif
char load_balance = 0, protocol_pedantic = 0;
#if NTLM_FAIL_OPEN
char last_ditch_enabled = 0;
#endif
dc *controllers = NULL;
int numcontrollers = 0;
dc *current_dc;
char smb_error_buffer[1000];


/* Disconnects from the DC. A reconnection will be done upon the next request
 */
void
dc_disconnect()
{
    if (handle != NULL)
        SMB_Discon(handle, 0);
    handle = NULL;
}

int
connectedp()
{
    return (handle != NULL);
}

/* Tries to connect to a DC. Returns 0 on failure, 1 on OK */
int
is_dc_ok(char *domain, char *domain_controller)
{
    SMB_Handle_Type h = SMB_Connect_Server(NULL, domain_controller, domain);
    if (h == NULL)
        return 0;
    SMB_Discon(h, 0);
    return 1;
}

/* returns 0 on success, > 0 on failure */
static int
init_challenge(char *domain, char *domain_controller)
{
    int smberr;

    if (handle != NULL) {
        return 0;
    }
    debug("Connecting to server %s domain %s\n", domain_controller, domain);
    handle = SMB_Connect_Server(NULL, domain_controller, domain);
    smberr = SMB_Get_Last_Error();
    SMB_Get_Error_Msg(smberr, errstr, 1000);


    if (handle == NULL) {	/* couldn't connect */
        debug("Couldn't connect to SMB Server. Error:%s\n", errstr);
        return 1;
    }
    if (SMB_Negotiate(handle, SMB_Prots) < 0) {		/* An error */
        debug("Error negotiating protocol with SMB Server\n");
        SMB_Discon(handle, 0);
        handle = NULL;
        return 2;
    }
    if (handle->Security == 0) {	/* share-level security, unuseable */
        debug("SMB Server uses share-level security .. we need user security.\n");
        SMB_Discon(handle, 0);
        handle = NULL;
        return 3;
    }
    memcpy(challenge, handle->Encrypt_Key, NTLM_NONCE_LEN);
    SMBencrypt((unsigned char *)"",challenge,lmencoded_empty_pass);
    SMBNTencrypt((unsigned char *)"",challenge,ntencoded_empty_pass);
    return 0;
}

const char *
make_challenge(char *domain, char *domain_controller)
{
    /* trying to circumvent some strange problem wih pointers in SMBLib */
    /* Ugly as hell, but the lib is going to be dropped... */
    strcpy(my_domain,domain);
    strcpy(my_domain_controller,domain_controller);
    if (init_challenge(my_domain, my_domain_controller) > 0) {
        return NULL;
    }
    ntlm_challenge chal;
    uint32_t flags = NTLM_REQUEST_NON_NT_SESSION_KEY |
                     NTLM_CHALLENGE_TARGET_IS_DOMAIN |
                     NTLM_NEGOTIATE_ALWAYS_SIGN |
                     NTLM_NEGOTIATE_USE_NTLM |
                     NTLM_NEGOTIATE_USE_LM |
                     NTLM_NEGOTIATE_ASCII;
    ntlm_make_challenge(&chal, my_domain, my_domain_controller, (char *)challenge, NTLM_NONCE_LEN, flags);
    int len = sizeof(chal) - sizeof(chal.payload) + le16toh(chal.target.maxlen);
    return base64_encode_bin((char *)&chal, len);
}

/* returns NULL on failure, or a pointer to
 * the user's credentials (domain\\username)
 * upon success. WARNING. It's pointing to static storage.
 * In case of problem sets as side-effect ntlm_errno to one of the
 * codes defined in ntlm.h
 */
char *
ntlm_check_auth(ntlm_authenticate * auth, int auth_length)
{
    int rv;
    char pass[MAX_PASSWD_LEN+1];
    char *domain = credentials;
    char *user;
    lstring tmp;

    if (handle == NULL) {	/*if null we aren't connected, but it shouldn't happen */
        debug("Weird, we've been disconnected\n");
        ntlm_errno = NTLM_ERR_NOT_CONNECTED;
        return NULL;
    }

    /*      debug("fetching domain\n"); */
    tmp = ntlm_fetch_string(&(auth->hdr), auth_length, &auth->domain, auth->flags);
    if (tmp.str == NULL || tmp.l == 0) {
        debug("No domain supplied. Returning no-auth\n");
        ntlm_errno = NTLM_ERR_LOGON;
        return NULL;
    }
    if (tmp.l > MAX_DOMAIN_LEN) {
        debug("Domain string exceeds %d bytes, rejecting\n", MAX_DOMAIN_LEN);
        ntlm_errno = NTLM_ERR_LOGON;
        return NULL;
    }
    memcpy(domain, tmp.str, tmp.l);
    user = domain + tmp.l;
    *user++ = '\0';

    /*      debug("fetching user name\n"); */
    tmp = ntlm_fetch_string(&(auth->hdr), auth_length, &auth->user, auth->flags);
    if (tmp.str == NULL || tmp.l == 0) {
        debug("No username supplied. Returning no-auth\n");
        ntlm_errno = NTLM_ERR_LOGON;
        return NULL;
    }
    if (tmp.l > MAX_USERNAME_LEN) {
        debug("Username string exceeds %d bytes, rejecting\n", MAX_USERNAME_LEN);
        ntlm_errno = NTLM_ERR_LOGON;
        return NULL;
    }
    memcpy(user, tmp.str, tmp.l);
    *(user + tmp.l) = '\0';


    /* Authenticating against the NT response doesn't seem to work... */
    tmp = ntlm_fetch_string(&(auth->hdr), auth_length, &auth->lmresponse, auth->flags);
    if (tmp.str == NULL || tmp.l == 0) {
        fprintf(stderr, "No auth at all. Returning no-auth\n");
        ntlm_errno = NTLM_ERR_LOGON;
        return NULL;
    }
    if (tmp.l > MAX_PASSWD_LEN) {
        debug("Password string exceeds %d bytes, rejecting\n", MAX_PASSWD_LEN);
        ntlm_errno = NTLM_ERR_LOGON;
        return NULL;
    }

    memcpy(pass, tmp.str, tmp.l);
    pass[min(MAX_PASSWD_LEN,tmp.l)] = '\0';

#if 1
    debug("Empty LM pass detection: user: '%s', ours:'%s', his: '%s' (length: %d)\n",
          user,lmencoded_empty_pass,tmp.str,tmp.l);
    if (memcmp(tmp.str,lmencoded_empty_pass,ENCODED_PASS_LEN)==0) {
        fprintf(stderr,"Empty LM password supplied for user %s\\%s. "
                "No-auth\n",domain,user);
        ntlm_errno=NTLM_ERR_LOGON;
        return NULL;
    }

    tmp = ntlm_fetch_string(&(auth->hdr), auth_length, &auth->ntresponse, auth->flags);
    if (tmp.str != NULL && tmp.l != 0) {
        debug("Empty NT pass detection: user: '%s', ours:'%s', his: '%s' (length: %d)\n",
              user,ntencoded_empty_pass,tmp.str,tmp.l);
        if (memcmp(tmp.str,lmencoded_empty_pass,ENCODED_PASS_LEN)==0) {
            fprintf(stderr,"ERROR: Empty NT password supplied for user %s\\%s. No-auth\n", domain, user);
            ntlm_errno = NTLM_ERR_LOGON;
            return NULL;
        }
    }
#endif

    /* TODO: check against empty password!!!!! */


    debug("checking domain: '%s', user: '%s', pass='%s'\n", domain, user, pass);

    rv = SMB_Logon_Server(handle, user, pass, domain, 1);
    debug("Login attempt had result %d\n", rv);

    if (rv != NTLM_ERR_NONE) {	/* failed */
        ntlm_errno = rv;
        return NULL;
    }
    *(user - 1) = '\\';		/* hack. Performing, but ugly. */

    debug("credentials: %s\n", credentials);
    return credentials;
}

extern "C" void timeout_during_auth(int signum);

static char got_timeout = 0;
/** signal handler to be invoked when the authentication operation
 * times out */
void
timeout_during_auth(int signum)
{
    dc_disconnect();
}

void
send_bh_or_ld(char const *bhmessage, ntlm_authenticate * failedauth, int authlen)
{
#if NTLM_FAIL_OPEN
    char user[NTLM_MAX_FIELD_LENGTH];
    char domain[NTLM_MAX_FIELD_LENGTH];
    if (last_ditch_enabled) {
        user[0] = '\0';
        domain[0] = '\0';
        if (ntlm_unpack_auth(failedauth, user, domain, authlen) == 0) {
            lc(domain);
            lc(user);
            SEND3("LD %s%s%s", domain, (domain[0]!='\0'?"//":""), user);
        } else {
            SEND("NA last-ditch on, but no credentials");
        }
    } else {
#endif
        SEND2("BH %s", bhmessage);
#if NTLM_FAIL_OPEN
    }
#endif
}

/*
 * options:
 * -b try load-balancing the domain-controllers
 * -f fail-over to another DC if DC connection fails.
 *    DEPRECATED and VERBOSELY IGNORED. This is on by default now.
 * -l last-ditch-mode
 * domain\controller ...
 */
char *my_program_name = NULL;

void
usage()
{
    fprintf(stderr,
            "%s usage:\n%s [-b] [-f] [-d] [-l] domain\\controller [domain\\controller ...]\n"
            "-b enables load-balancing among controllers\n"
            "-f enables failover among controllers (DEPRECATED and always active)\n"
            "-l changes behavior on domain controller failyures to last-ditch.\n"
            "-d enables debugging statements if DEBUG was defined at build-time.\n\n"
            "You MUST specify at least one Domain Controller.\n"
            "You can use either \\ or / as separator between the domain name \n"
            "and the controller name\n",
            my_program_name, my_program_name);
}

/* int debug_enabled=0; defined in libcompat */

void
process_options(int argc, char *argv[])
{
    int opt, j, had_error = 0;
    dc *new_dc = NULL, *last_dc = NULL;
    while (-1 != (opt = getopt(argc, argv, "bfld"))) {
        switch (opt) {
        case 'b':
            load_balance = 1;
            break;
        case 'f':
            fprintf(stderr,
                    "WARNING. The -f flag is DEPRECATED and always active.\n");
            break;
#if NTLM_FAIL_OPEN
        case 'l':
            last_ditch_enabled = 1;
            break;
#endif
        case 'd':
            debug_enabled=1;
            break;
        default:
            fprintf(stderr, "unknown option: -%c. Exiting\n", opt);
            usage();
            had_error = 1;
        }
    }
    if (had_error)
        exit(1);
    /* Okay, now begin filling controllers up */
    /* we can avoid memcpy-ing, and just reuse argv[] */
    for (j = optind; j < argc; ++j) {
        char *d, *c;
        /* d will not be freed in case of non-error. Since we don't reconfigure,
         * it's going to live as long as the process anyways */
        d = (char*)malloc(strlen(argv[j]) + 1);
        strcpy(d, argv[j]);
        debug("Adding domain-controller %s\n", d);
        if (NULL == (c = strchr(d, '\\')) && NULL == (c = strchr(d, '/'))) {
            fprintf(stderr, "Couldn't grok domain-controller %s\n", d);
            free(d);
            continue;
        }
        /* more than one delimiter is not allowed */
        if (NULL != strchr(c + 1, '\\') || NULL != strchr(c + 1, '/')) {
            fprintf(stderr, "Broken domain-controller %s\n", d);
            free(d);
            continue;
        }
        *c++ = '\0';
        new_dc = (dc *) malloc(sizeof(dc));
        if (!new_dc) {
            fprintf(stderr, "Malloc error while parsing DC options\n");
            free(d);
            continue;
        }
        /* capitalize */
        uc(c);
        uc(d);
        ++numcontrollers;
        new_dc->domain = d;
        new_dc->controller = c;
        new_dc->dead = 0;
        if (controllers == NULL) {	/* first controller */
            controllers = new_dc;
            last_dc = new_dc;
        } else {
            last_dc->next = new_dc;	/* can't be null */
            last_dc = new_dc;
        }
    }
    if (numcontrollers == 0) {
        fprintf(stderr, "You must specify at least one domain-controller!\n");
        usage();
        exit(1);
    }
    last_dc->next = controllers;	/* close the queue, now it's circular */
}

/**
 * tries connecting to the domain controllers in the "controllers" ring,
 * with failover if the adequate option is specified.
 */
const char *
obtain_challenge()
{
    int j = 0;
    const char *ch = NULL;
    for (j = 0; j < numcontrollers; ++j) {
        debug("obtain_challenge: selecting %s\\%s (attempt #%d)\n",
              current_dc->domain, current_dc->controller, j + 1);
        if (current_dc->dead != 0) {
            if (time(NULL) - current_dc->dead >= DEAD_DC_RETRY_INTERVAL) {
                /* mark helper as retry-worthy if it's so. */
                debug("Reviving DC\n");
                current_dc->dead = 0;
            } else {		/* skip it */
                debug("Skipping it\n");
                continue;
            }
        }
        /* else branch. Here we KNOW that the DC is fine */
        debug("attempting challenge retrieval\n");
        ch = make_challenge(current_dc->domain, current_dc->controller);
        debug("make_challenge retuned %p\n", ch);
        if (ch) {
            debug("Got it\n");
            return ch;		/* All went OK, returning */
        }
        /* Huston, we've got a problem. Take this DC out of the loop */
        debug("Marking DC as DEAD\n");
        current_dc->dead = time(NULL);
        /* Try with the next */
        debug("moving on to next controller\n");
        current_dc = current_dc->next;
    }
    /* all DCs failed. */
    return NULL;
}


void
manage_request()
{
    ntlmhdr *fast_header;
    char buf[NTLM_BLOB_BUFFER_SIZE];
    char decoded[NTLM_BLOB_BUFFER_SIZE];
    const char *ch;
    char *ch2, *cred = NULL;

    if (fgets(buf, NTLM_BLOB_BUFFER_SIZE, stdin) == NULL) {
        fprintf(stderr, "fgets() failed! dying..... errno=%d (%s)\n", errno,
                strerror(errno));
        exit(1);		/* BIIG buffer */
    }
    debug("managing request\n");
    ch2 = (char*)memchr(buf, '\n', NTLM_BLOB_BUFFER_SIZE);	/* safer against overrun than strchr */
    if (ch2) {
        *ch2 = '\0';		/* terminate the string at newline. */
        ch = ch2;
    }
    debug("ntlm authenticator. Got '%s' from Squid\n", buf);

    if (memcmp(buf, "KK ", 3) == 0) {	/* authenticate-request */
        /* figure out what we got */
        int decodedLen = base64_decode(decoded, sizeof(decoded), buf+3);

        if ((size_t)decodedLen < sizeof(ntlmhdr)) {	/* decoding failure, return error */
            SEND("NA Packet format error, couldn't base64-decode");
            return;
        }
        /* fast-track-decode request type. */
        fast_header = (ntlmhdr *) decoded;

        /* sanity-check: it IS a NTLMSSP packet, isn't it? */
        if (ntlm_validate_packet(fast_header, NTLM_ANY) < 0) {
            SEND("NA Broken authentication packet");
            return;
        }
        switch (le32toh(fast_header->type)) {
        case NTLM_NEGOTIATE:
            SEND("NA Invalid negotiation request received");
            return;
            /* notreached */
        case NTLM_CHALLENGE:
            SEND("NA Got a challenge. We refuse to have our authority disputed");
            return;
            /* notreached */
        case NTLM_AUTHENTICATE:
            /* check against the DC */
            signal(SIGALRM, timeout_during_auth);
            alarm(30);
            cred = ntlm_check_auth((ntlm_authenticate *) decoded, decodedLen);
            alarm(0);
            signal(SIGALRM, SIG_DFL);
            if (got_timeout != 0) {
                fprintf(stderr, "ntlm-auth[%ld]: Timeout during authentication.\n", (long)getpid());
                SEND("BH Timeout during authentication");
                got_timeout = 0;
                return;
            }
            if (cred == NULL) {
                int smblib_err, smb_errorclass, smb_errorcode, nb_error;
                if (ntlm_errno == NTLM_ERR_LOGON) {	/* hackish */
                    SEND("NA Logon Failure");
                    return;
                }
                /* there was an error. We have two errno's to look at.
                 * libntlmssp's erno is insufficient, we'll have to look at
                 * the actual SMB library error codes, to acually figure
                 * out what's happening. The thing has braindamaged interfacess..*/
                smblib_err = SMB_Get_Last_Error();
                smb_errorclass = SMBlib_Error_Class(SMB_Get_Last_SMB_Err());
                smb_errorcode = SMBlib_Error_Code(SMB_Get_Last_SMB_Err());
                nb_error = RFCNB_Get_Last_Error();
                debug("No creds. SMBlib error %d, SMB error class %d, SMB error code %d, NB error %d\n",
                      smblib_err, smb_errorclass, smb_errorcode, nb_error);
                /* Should I use smblib_err? Actually it seems I can do as well
                 * without it.. */
                if (nb_error != 0) {	/* netbios-level error */
                    send_bh_or_ld("NetBios error!",
                                  (ntlm_authenticate *) decoded, decodedLen);
                    fprintf(stderr, "NetBios error code %d (%s)\n", nb_error,
                            RFCNB_Error_Strings[abs(nb_error)]);
                    return;
                }
                switch (smb_errorclass) {
                case SMBC_SUCCESS:
                    debug("Huh? Got a SMB success code but could check auth..");
                    SEND("NA Authentication failed");
                    /*
                     * send_bh_or_ld("SMB success, but no creds. Internal error?",
                     * (ntlm_authenticate *) decoded, decodedLen);
                     */
                    return;
                case SMBC_ERRDOS:
                    /*this is the most important one for errors */
                    debug("DOS error\n");
                    switch (smb_errorcode) {
                        /* two categories matter to us: those which could be
                         * server errors, and those which are auth errors */
                    case SMBD_noaccess:	/* 5 */
                        SEND("NA Access denied");
                        return;
                    case SMBD_badformat:
                        SEND("NA bad format in authentication packet");
                        return;
                    case SMBD_badaccess:
                        SEND("NA Bad access request");
                        return;
                    case SMBD_baddata:
                        SEND("NA Bad Data");
                        return;
                    default:
                        send_bh_or_ld("DOS Error",
                                      (ntlm_authenticate *) decoded, decodedLen);
                        return;
                    }
                case SMBC_ERRSRV:	/* server errors */
                    debug("Server error");
                    switch (smb_errorcode) {
                        /* mostly same as above */
                    case SMBV_badpw:
                        SEND("NA Bad password");
                        return;
                    case SMBV_access:
                        SEND("NA Server access error");
                        return;
                    default:
                        send_bh_or_ld("Server Error",
                                      (ntlm_authenticate *) decoded, decodedLen);
                        return;
                    }
                case SMBC_ERRHRD:	/* hardware errors don't really matter */
                    send_bh_or_ld("Domain Controller Hardware error",
                                  (ntlm_authenticate *) decoded, decodedLen);
                    return;
                case SMBC_ERRCMD:
                    send_bh_or_ld("Domain Controller Command Error",
                                  (ntlm_authenticate *) decoded, decodedLen);
                    return;
                }
                SEND("BH unknown internal error.");
                return;
            }

            lc(cred);		/* let's lowercase them for our convenience */
            SEND2("AF %s", cred);
            return;
        default:
            SEND("BH unknown authentication packet type");
            return;
        }
        /* notreached */
        return;
    }
    if (memcmp(buf, "YR", 2) == 0) {	/* refresh-request */
        dc_disconnect();
        ch = obtain_challenge();
        /* Robert says we can afford to wait forever. I'll trust him on this
         * one */
        while (ch == NULL) {
            sleep(30);
            ch = obtain_challenge();
        }
        SEND2("TT %s", ch);
        return;
    }
    SEND("BH Helper detected protocol error");
    return;
    /********* END ********/


}

int
main(int argc, char *argv[])
{
    debug("ntlm_auth build " __DATE__ ", " __TIME__ " starting up...\n");

    my_program_name = argv[0];
    process_options(argc, argv);

    debug("options processed OK\n");

    /* initialize FDescs */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* select the first domain controller we're going to use */
    current_dc = controllers;
    if (load_balance != 0 && numcontrollers > 1) {
        int n;
        pid_t pid = getpid();
        n = pid % numcontrollers;
        debug("load balancing. Selected controller #%d\n", n);
        while (n > 0) {
            current_dc = current_dc->next;
            --n;
        }
    }
    while (1) {
        manage_request();
    }
    /* notreached */
    return 0;
}