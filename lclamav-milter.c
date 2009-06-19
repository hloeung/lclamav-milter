/**
 * $Id$
 *
 * lclamav-milter.c - lightweight sendmail Clam AntiVirus milter
 * <http://lclamav-milter.sourceforge.net/>
 *
 * Copyright 2007, 2008, 2009 Haw Loeung <hloeung@users.sourceforge.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <clamav.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "libmilter/mfapi.h"
#define GETCONTEXT(ctx)  ((struct mlfiPriv *) smfi_getpriv(ctx))

struct rcptNode {
	char *addr;
	struct rcptNode *next;
};

#define STAMP_NONE          0
#define STAMP_SIZE_EXCEEDED 1
typedef uint8_t stamp_t;
#define STAMP_HEADER_STATUS "X-lClamAV-AntiVirus"

struct mlfiPriv {
	char *connectfrom;
	char *connectaddr;
	char *daemonname;
	char *msgid;
	char *envfrom;
	uint8_t rcptcnt;
	struct rcptNode *rcpth;
	struct rcptNode *rcptt;
	char *fname;
	FILE *fp;
	size_t msgsize;
	uint8_t check;
	stamp_t stamp;
};

sfsistat mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
sfsistat mlfi_envfrom(SMFICTX *, char **);
sfsistat mlfi_envrcpt(SMFICTX *, char **);
sfsistat mlfi_header(SMFICTX *, char *, char *);
sfsistat mlfi_eoh(SMFICTX *);
sfsistat mlfi_body(SMFICTX *, unsigned char *, size_t);
sfsistat mlfi_eom(SMFICTX *);
sfsistat mlfi_abort(SMFICTX *);
sfsistat mlfi_close(SMFICTX *);
sfsistat mlfi_data(SMFICTX *);
static sfsistat mlfi_cleanup(SMFICTX *);

struct smfiDesc smfilter = {
	"lclamav-milter",	/* filter name */
	SMFI_VERSION,		/* version code -- do not change */
	SMFIF_ADDHDRS,		/* flags */
	mlfi_connect,		/* connection info filter */
	NULL,			/* SMTP HELO command filter */
	mlfi_envfrom,		/* envelope sender filter */
	mlfi_envrcpt,		/* envelope recipient filter */
	mlfi_header,		/* header filter */
	mlfi_eoh,		/* end of header */
	mlfi_body,		/* body block filter */
	mlfi_eom,		/* end of message */
	mlfi_abort,		/* message aborted */
	mlfi_close,		/* connection cleanup */
	NULL,			/* unknown SMTP commands */
	mlfi_data,		/* DATA command */
	NULL,			/* Once, at the start of each SMTP
				   connection */
};

static void usage(const char *);
static void mlog(const int, const char *, ...);
static void daemonize(void);
static int drop_privs(const char *, const char *);
static void pidf_create(const char *);
static void pidf_destroy(const char *);
static int dn_check(const char *);
static char *msg_create(const char *, const char *);

#ifdef __linux__
# define HAS_LONGOPT 1
# include <getopt.h>
#else
# define getopt_long(argc,argv,opts,lopt,lind) getopt(argc,argv,opts)
#endif

#define BUFLEN 64
#define MAXRETRY 3

struct config {
	char *pname;
	uint8_t daemon;
	ssize_t maxsize;
	char *tmpdir;
	int timeout;
} config;

struct cl_engine *av_engine;
unsigned int av_sigs;

/* Default TEMPFAIL messages (used when unable to scan msg) */
char *smtp_temp_fail_rcode = "452";
char *smtp_temp_fail_xcode = "4.2.1";
char *smtp_temp_fail_msg =
    "Antivirus software failed to scan message - Please try again later";

/* Default REJECT messages (used when viruses were detected) */
char *smtp_perm_fail_rcode = "554";
char *smtp_perm_fail_xcode = "5.6.1";
char *smtp_perm_fail_msg =
    "One or more viruses were detected in this message. To prevent further infections, we will not allow relaying of messages that contains a virus. Details: ";

int main(int argc, char **argv)
{
	extern char *optarg;
	const char *opts = "b:D:dg:hm:s:T:t:u:";
#ifdef HAS_LONGOPT
	static const struct option lopt[] = {
		{"bind", 1, 0, 'b'},
		{"debug", 1, 0, 'D'},
		{"daemonize", 0, 0, 'd'},
		{"group", 1, 0, 'g'},
		{"help", 0, 0, 'h'},
		{"max-size", 1, 0, 'm'},
		{"tmp-dir", 1, 0, 'T'},
		{"timeout", 1, 0, 't'},
		{"user", 1, 0, 'u'},
		{NULL, 0, 0, 0}
	};
#endif
	int c;
	char *p;
	char *oconn;
	int setconn;
	int len;
	int ret;
	uint8_t daemon;
	char *usr;
	char *grp;
	char *pidf = "/var/run/milter/lclamav-milter.pid";

	p = strrchr(argv[0], '/');
	if (p == NULL)
		config.pname = argv[0];
	else
		config.pname = p + 1;

	if (argc < 2) {
		usage(config.pname);
		exit(EX_USAGE);
	}

	setconn = 0;
	oconn = NULL;
	config.daemon = 0;
	config.maxsize = 2097152;
	config.tmpdir = NULL;
	config.timeout = 120;
	daemon = 0;
	usr = grp = NULL;

	while ((c = getopt_long(argc, argv, opts, lopt, NULL)) != -1) {

		switch (c) {

		case 'b':	/* bind address/socket */
			if (setconn) {
				mlog(LOG_ERR,
				     "Bind address/socket already provided, ignoring");
				break;
			}

			if ((optarg == NULL) || (*optarg == '\0')) {
				mlog(LOG_ERR,
				     "No bind address/socket provided\n");
				usage(config.pname);
				exit(EX_USAGE);
			}

			if ((strncmp(optarg, "unix:", 5) == 0) ||
			    (strncmp(optarg, "local:", 6) == 0) ||
			    (strncmp(optarg, "inet:", 5) == 0) ||
			    (strncmp(optarg, "inet6:", 6) == 0)) {
				oconn = optarg;
				setconn = 1;
				break;
			}

			/* "unix:" + optarg + '\0' */
			len = 5 + strlen(optarg) + 1;
			oconn = malloc(len);
			if (oconn == NULL) {
				mlog(LOG_ERR, "Memory allocation failed");
				exit(EX_UNAVAILABLE);
			}

			snprintf(oconn, len, "unix:%s", optarg);
			setconn = 2;
			break;

		case 'D':
			if ((optarg == NULL) || (*optarg == '\0')) {
				mlog(LOG_ERR,
				     "No debugging level provided\n");
				usage(config.pname);
				exit(EX_USAGE);
			}

			smfi_setdbg(atoi(optarg));
			break;

		case 'd':
			daemon = 1;
			break;

		case 'g':
			if ((optarg == NULL) || (*optarg == '\0')) {
				mlog(LOG_ERR, "No group provided\n");
				usage(config.pname);
				exit(EX_USAGE);
			}

			grp = optarg;
			break;

		case 'm':
			if ((optarg == NULL) || (*optarg == '\0')) {
				mlog(LOG_ERR, "No size provided\n");
				usage(config.pname);
				exit(EX_USAGE);
			}

			config.maxsize = atoi(optarg);

			if (config.maxsize < 0) {
				mlog(LOG_ERR, "Invalid size provided\n");
				usage(config.pname);
				exit(EX_USAGE);
			}
			break;

		case 'T':
			if ((optarg == NULL) || (*optarg == '\0')) {
				mlog(LOG_ERR, "No directory provided\n");
				usage(config.pname);
				exit(EX_USAGE);
			}

			config.tmpdir = optarg;
			break;

		case 't':
			if ((optarg == NULL) || (*optarg == '\0')) {
				mlog(LOG_ERR, "No timeout provided\n");
				usage(config.pname);
				exit(EX_USAGE);
			}

			config.timeout = atoi(optarg);
			smfi_settimeout(config.timeout);
			break;

		case 'u':
			if ((optarg == NULL) || (*optarg == '\0')) {
				mlog(LOG_ERR, "No user provided\n");
				usage(config.pname);
				exit(EX_USAGE);
			}

			usr = optarg;
			break;

		case 'h':	/* help */
		default:
			usage(config.pname);
			exit(EX_USAGE);
		}
	}

	if (setconn == 0) {
		mlog(LOG_ERR, "%s: Missing required bind address/socket\n",
		     config.pname);
		usage(config.pname);
		exit(EX_USAGE);
	}

	if (config.tmpdir == NULL) {
		mlog(LOG_ERR, "%s: Missing temporary directory\n",
		     config.pname);
		usage(config.pname);
		exit(EX_USAGE);
	}

	av_sigs = 0;
#ifdef DEBUG
	cl_debug();
#endif
	cl_init(0);
	av_engine = cl_engine_new();
	cl_engine_set_str(av_engine, CL_ENGINE_TMPDIR, config.tmpdir);
	cl_engine_set_num(av_engine, CL_ENGINE_KEEPTMP, 0);
	ret = cl_load(cl_retdbdir(), av_engine, &av_sigs,
		      CL_DB_STDOPT | CL_DB_PHISHING);
	if (ret != CL_SUCCESS) {
		mlog(LOG_ERR, "Unable to load ClamAV database: %s",
		     cl_strerror(ret));
		exit(EX_UNAVAILABLE);
	}

	ret = cl_engine_compile(av_engine);
	if (ret != CL_SUCCESS) {
		mlog(LOG_ERR,
		     "Unable to prepare ClamAV detection engine: %s",
		     cl_strerror(ret));
		cl_engine_free(av_engine);
		exit(EX_UNAVAILABLE);
	}

	cl_engine_set_num(av_engine, CL_ENGINE_MAX_RECURSION, 8);
	cl_engine_set_num(av_engine, CL_ENGINE_MAX_FILES, 1000);
	cl_engine_set_num(av_engine, CL_ENGINE_MAX_FILESIZE,
			  config.maxsize);

	umask(0027);

	if (smfi_setconn(oconn) == MI_FAILURE) {
		mlog(LOG_ERR, "smfi_setconn() failed");
		exit(EX_UNAVAILABLE);
	}

	if (smfi_register(smfilter) == MI_FAILURE) {
		mlog(LOG_ERR, "smfi_register() failed");
		exit(EX_UNAVAILABLE);
	}

	if (usr || grp)
		if (drop_privs(usr, grp))
			exit(EX_TEMPFAIL);

	if (daemon)
		daemonize();

	/* write pid file */
	pidf_create(pidf);

	mlog(LOG_INFO, "Starting Sendmail %s filter '%s'",
	     smfilter.xxfi_name, config.pname);
	mlog(LOG_INFO, "$Id$");
	mlog(LOG_INFO, "libclamav (ver. %s) loaded with %d signatures",
	     cl_retver(), av_sigs);

	ret = smfi_main();
	/* remove pid file */
	pidf_destroy(pidf);
	if (ret == MI_SUCCESS) {
		mlog(LOG_INFO, "Stopping Sendmail %s filter '%s'",
		     smfilter.xxfi_name, config.pname);
	} else {
		mlog(LOG_ERR,
		     "Abnormal termination of Sendmail %s filter '%s': %d",
		     smfilter.xxfi_name, config.pname, ret);
	}

	if (setconn == 2) {
		free(oconn);
		oconn = NULL;
	}

	if (daemon)
		closelog();

	if (av_engine != NULL)
		cl_engine_free(av_engine);

	return ret;
}

static void usage(const char *prog)
{
	printf("\
Usage: %s -b [bind address/socket] [-dh] [-D [debug level]]\n\
       [-t [milter timeout in seconds] [-u [user]] [-g [group]] \n", prog);

	printf("\n\
    -b addr/socket  Bind address or UNIX socket. E.g. inet:1234@127.0.0.1\n\
\n\
    -d              Daemonize and run in the background. Default runs milter\n\
                    in foreground\n\
    -D level        Set milter library's internal debugging level. (max: 6)\n\
    -m size         Sets the maximum message size to scan for viruses in bytes\n\
                    (default: 250000)\n\
    -t seconds      Sets the number of seconds libmilter will wait for an MTA\n\
                    connection before timing out a socket. (default: 7210)\n\
    -u user         Run as user \"user\"\n\
    -g group        Run as group \"group\"\n\
\n\
    -h              This help screen\n");

	printf("\nReport bugs to Haw Loeung <hloeung@users.sourceforge.net>\n\
$Id$\n\
libclamav version: %s\n", cl_retver());

}

static void mlog(const int priority, const char *fmt, ...)
{
	char tbuf[15];
	time_t t;
	struct tm tm;
	va_list ap;

	va_start(ap, fmt);

	/* if daemonize, then we log to syslog */
	if (config.daemon)
		vsyslog(priority, fmt, ap);

	else {
		t = time(NULL);
		strftime(tbuf, sizeof(tbuf), "%b %e %T", localtime_r(&t, &tm));
		fprintf(stderr, "%.15s ", tbuf);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
	}

	va_end(ap);
}

sfsistat mlfi_connect(SMFICTX * ctx, char *hostname, _SOCK_ADDR * hostaddr)
{
	struct mlfiPriv *priv;
	char *p;
	struct sockaddr_in *phostaddr;
	uint32_t saddr;
	size_t len;

	/* allocate some private memory */
	priv = malloc(sizeof *priv);
	if (priv == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed", hostname,
		     "mlfi_connect()");
		return SMFIS_ACCEPT;
	}
	memset(priv, '\0', sizeof *priv);

	/* set the private data pointer */
	smfi_setpriv(ctx, priv);

	/* store hostname of the SMTP client */
	priv->connectfrom = strdup(hostname);
	if (priv->connectfrom == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed", hostname,
		     "mlfi_connect()");
		return SMFIS_ACCEPT;
	}

	/*
	 * now we need the validated sender's address and daemon name so we
	 * could use later to forge the "Received" header line
	 */
	p = smfi_getsymval(ctx, "{_}");
	if (p == NULL) {
		/* failed to get symbol, so we use hostaddr */
		phostaddr = (struct sockaddr_in *) hostaddr;
		saddr = htonl(phostaddr->sin_addr.s_addr);

		/* "unknown [xxx.xxx.xxx.xxx]" + '\0' */
		p = malloc(26);
		if (p == NULL) {
			mlog(LOG_ERR, "%s: %s: Memory allocation failed",
			     hostname, "mlfi_connect()");
			return SMFIS_ACCEPT;
		}
		snprintf(p, 18, "unknown [%d.%d.%d.%d]",
			 (saddr & 0xff000000) >> 24,
			 (saddr & 0x00ff0000) >> 16,
			 (saddr & 0x0000ff00) >> 8,
			 (saddr & 0x000000ff));
		priv->connectaddr = p;
	}

	else {
		/* fix for when the "_" macro contains just an IP address */
		if (strncmp(p, "[", 1) == 0) {
			len = strlen(p) + 8 + 1;
			priv->connectaddr = malloc(len);
			if (priv->connectaddr == NULL) {
				mlog(LOG_ERR,
				     "%s: %s: Memory allocation failed",
				     hostname, "mlfi_connect()");
				return SMFIS_ACCEPT;
			}

			snprintf(priv->connectaddr, len, "unknown %s", p);
		}

		else {
			/* store sender host address */
			priv->connectaddr = strdup(p);
			if (priv->connectaddr == NULL) {
				mlog(LOG_ERR,
				     "%s: %s: Memory allocation failed",
				     hostname, "mlfi_connect()");
				return SMFIS_ACCEPT;
			}
		}
	}

	p = smfi_getsymval(ctx, "{daemon_name}");
	if (p == NULL) {
		mlog(LOG_ERR, "%s: %s: Retrieve symbol '%s' failed",
		     hostname, "mlfi_connect()", "{daemon_name}");
		return SMFIS_ACCEPT;
	}

	/* store daemon name */
	priv->daemonname = strdup(p);
	if (priv->daemonname == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed", hostname,
		     "mlfi_connect()");
		return SMFIS_ACCEPT;
	}

	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat mlfi_envfrom(SMFICTX * ctx, char **argv)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);
	char *p;

	/* store message ID */
	p = smfi_getsymval(ctx, "{i}");
	if (p == NULL) {
		mlog(LOG_ERR, "%s: %s: Retrieve symbol '%s' failed",
		     priv->connectfrom, "mlfi_envfrom()", "{i}");
		mlfi_cleanup(ctx);
		return SMFIS_ACCEPT;
	}
	priv->msgid = strdup(p);
	if (priv->msgid == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed",
		     priv->connectfrom, "mlfi_envfrom()");
		mlfi_cleanup(ctx);
		return SMFIS_ACCEPT;
	}

	/* store sender's address */
	priv->envfrom = strdup(argv[0]);
	if (priv->envfrom == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed",
		     priv->msgid, "mlfi_envfrom()");
		mlfi_cleanup(ctx);
		return SMFIS_ACCEPT;
	}

	priv->check = 1;

	priv->rcptcnt = 0;
	priv->rcpth = priv->rcptt = NULL;

	return SMFIS_CONTINUE;
}

sfsistat mlfi_envrcpt(SMFICTX * ctx, char **argv)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);
	struct rcptNode *rcpt;

	rcpt = calloc(1, sizeof *rcpt);
	if (rcpt == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed",
		     priv->msgid, "mlfi_envrcpt()");
		mlfi_cleanup(ctx);
		return SMFIS_ACCEPT;
	}

	/* store recipient's address */
	rcpt->addr = strdup(argv[0]);
	if (rcpt->addr == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed",
		     priv->msgid, "mlfi_envrcpt()");
		mlfi_cleanup(ctx);
		return SMFIS_ACCEPT;
	}

	rcpt->next = NULL;

	/* attach it to the end of our linked-list */
	if (priv->rcptt == NULL)
		priv->rcpth = priv->rcptt = rcpt;
	else {
		(priv->rcptt)->next = rcpt;
		priv->rcptt = rcpt;
	}

	priv->rcptcnt++;

	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat mlfi_header(SMFICTX * ctx, char *headerf, char *headerv)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);

	if (priv->check == 0)
		return SMFIS_CONTINUE;

	if (fprintf(priv->fp, "%s: %s\r\n", headerf, headerv) == EOF) {
		mlog(LOG_ERR, "%s: %s: Unable to write message headers",
		     priv->msgid, "mlfi_header()");
		mlfi_cleanup(ctx);
		return SMFIS_ACCEPT;
	}

	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat mlfi_eoh(SMFICTX * ctx)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);

	if (priv->check == 0)
		return SMFIS_CONTINUE;

	/* output the blank line between the header and the body */
	if (fprintf(priv->fp, "\r\n") == EOF) {
		mlog(LOG_ERR, "%s: %s: Unable to write empty line",
		     priv->msgid, "mlfi_eoh()");
		mlfi_cleanup(ctx);
		return SMFIS_ACCEPT;
	}

	priv->msgsize += 2;

	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat mlfi_body(SMFICTX * ctx, unsigned char *bodyp, size_t len)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);

	if (priv->check == 0)
		return SMFIS_CONTINUE;

	/*
	 * again, if the message size exceeds maximum size, then we don't
	 * check
	 */
	if ((priv->msgsize > (size_t) config.maxsize)
	    || (priv->msgsize + len > (size_t) config.maxsize)) {
		priv->check = 0;
		priv->stamp = STAMP_SIZE_EXCEEDED;
		return SMFIS_CONTINUE;
	}

	if (fwrite(bodyp, len, 1, priv->fp) != 1) {
		mlog(LOG_ERR, "%s: %s: Unable to write msg body",
		     priv->msgid, "mlfi_body()");
		mlfi_cleanup(ctx);
		return SMFIS_CONTINUE;
	}

	priv->msgsize += len;
	return SMFIS_CONTINUE;
}

sfsistat mlfi_eom(SMFICTX * ctx)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);
	const char *virname = NULL;
	int ret;
	unsigned int i;
	char *p;
	struct rcptNode *pnode;

	/*
	 * again, if the message size exceeds maximum size, then we don't
	 * check. Shouldn't get here, but just incase
	 */
	if (priv->msgsize > (size_t) config.maxsize) {
		priv->check = 0;
		priv->stamp = STAMP_SIZE_EXCEEDED;
	}

	/* not checking for virus, so we stamp it with a few things */
	if (priv->check == 0) {

		switch (priv->stamp) {
		case STAMP_SIZE_EXCEEDED:
			smfi_insheader(ctx, 0, STAMP_HEADER_STATUS,
				       "Message not scanned because message size too large");
			break;
		default:
			smfi_insheader(ctx, 0, STAMP_HEADER_STATUS,
				       "Unknown error");
			break;
		}

		return mlfi_cleanup(ctx);
	}

	/* flush buffers so then we can run the scan */
	fflush(priv->fp);

	for (i = MAXRETRY; i > 0; i--) {

		ret = cl_scanfile(priv->fname, &virname, NULL,
				  av_engine, CL_SCAN_STDOPT
				  | CL_SCAN_ARCHIVE
				  | CL_SCAN_MAIL
				  | CL_SCAN_OLE2
				  | CL_SCAN_HTML
				  | CL_SCAN_PE
				  | CL_SCAN_ALGORITHMIC | CL_SCAN_ELF);

		if ((ret == CL_CLEAN) || (ret == CL_VIRUS))
			break;
	}

	/* skip messages with oversized archive attachments */
	if ((virname != NULL) && (*virname == 'O')
	    && (strlen(virname) == 13)
	    && (strncmp(virname, "Oversized.Zip", 13) == 0)) {
		mlog(LOG_INFO,
		     "%s: Oversized zip: from=%s, size=%d, relay=%s, nrcpts=%d",
		     priv->msgid, priv->envfrom, priv->msgsize,
		     priv->connectaddr, priv->rcptcnt);
		ret = CL_CLEAN;
	}

	switch (ret) {
	case CL_CLEAN:		/* No viruses were found */
		smfi_insheader(ctx, 0, STAMP_HEADER_STATUS, "Passed");
		break;

	case CL_VIRUS:		/* Oh-o! Virus found */
		/* for each recipient, log */
		pnode = priv->rcpth;
		while (pnode != NULL) {
			mlog(LOG_ERR,
			     "%s: Virus alert: from=%s, size=%d, relay=%s, nrcpts=%d, to=%s, info=<infected:%s>",
			     priv->msgid, priv->envfrom, priv->msgsize,
			     priv->connectaddr, priv->rcptcnt, pnode->addr,
			     virname);
			pnode = pnode->next;
		}

		p = msg_create(smtp_perm_fail_msg, virname);
		if (p == NULL) {
			mlog(LOG_ERR, "%s: %s: Memory allocation failed",
			     priv->msgid, "mlfi_eom()");
			smfi_setreply(ctx, smtp_temp_fail_rcode,
				      smtp_temp_fail_xcode,
				      smtp_temp_fail_msg);
			mlfi_cleanup(ctx);
			return SMFIS_TEMPFAIL;
		}

		smfi_setreply(ctx, smtp_perm_fail_rcode,
			      smtp_perm_fail_xcode, p);
		free(p);
		p = NULL;
		mlfi_cleanup(ctx);
		return SMFIS_REJECT;
		break;

	default:		/* Failed to scan message */
		mlog(LOG_ERR, "%s: Unable to scan message: %s",
		     priv->msgid, cl_strerror(ret));

		/* daemon name beings with "mail" so we don't tempfail */
		if (dn_check(priv->daemonname))
			smfi_insheader(ctx, 0, STAMP_HEADER_STATUS,
				       "Not scanned");
		else {
			smfi_setreply(ctx, smtp_temp_fail_rcode,
				      smtp_temp_fail_xcode,
				      smtp_temp_fail_msg);
			mlfi_cleanup(ctx);
			return SMFIS_TEMPFAIL;
		}
		break;
	}

	return mlfi_cleanup(ctx);
}

sfsistat mlfi_abort(SMFICTX * ctx)
{
	return mlfi_cleanup(ctx);
}

sfsistat mlfi_close(SMFICTX * ctx)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);

	if (priv == NULL)
		return SMFIS_CONTINUE;

	/* mlfi_connect() */
	if (priv->connectfrom != NULL) {
		free(priv->connectfrom);
		priv->connectfrom = NULL;
	}
	if (priv->connectaddr != NULL) {
		free(priv->connectaddr);
		priv->connectaddr = NULL;
	}
	if (priv->daemonname != NULL) {
		free(priv->daemonname);
		priv->daemonname = NULL;
	}

	free(priv);
	priv = NULL;
	smfi_setpriv(ctx, NULL);

	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat mlfi_data(SMFICTX * ctx)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);
	const char *fprefix = "clamav";
	size_t fnsize;
	int fd;

	/* config.tmpdir + "/" + fprefix + "." + priv->msgid + "." + "XXXXXX"
	   + '\0' */
	fnsize = strlen(config.tmpdir) + 1 + strlen(fprefix) + 1
	    + strlen(priv->msgid) + 1 + 6 + 1;

	priv->fname = malloc(fnsize);
	if (priv->fname == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed",
		     priv->msgid, "mlfi_data()");
		mlfi_cleanup(ctx);
		return SMFIS_ACCEPT;
	}

	snprintf(priv->fname, fnsize, "%s/%s.%s.XXXXXX", config.tmpdir,
		 fprefix, priv->msgid);

	/* create temp file */
	fd = mkstemp(priv->fname);
	if (fd == -1) {
		mlog(LOG_ERR, "%s: %s: Unable to create file %s: %s",
		     priv->msgid, "mlfi_data()", priv->fname,
		     strerror(errno));
		mlfi_cleanup(ctx);
		return SMFIS_ACCEPT;
	}

	/* adjust permissions */
	if (chmod(priv->fname, S_IWUSR | S_IRUSR | S_IRGRP | S_IWGRP) ==
	    -1) {
		mlog(LOG_ERR,
		     "%s: %s: Unable to set file permissions %s: %s",
		     priv->msgid, "mlfi_data()", priv->fname,
		     strerror(errno));
		close(fd);
		mlfi_cleanup(ctx);
		return SMFIS_ACCEPT;
	}

	priv->fp = fdopen(fd, "w+");
	if (priv->fp == NULL) {
		mlog(LOG_ERR, "%s: %s: Unable to open file %s: %s",
		     priv->msgid, "mlfi_data()", priv->fname,
		     strerror(errno));
		close(fd);
		mlfi_cleanup(ctx);
		return SMFIS_ACCEPT;
	}

	priv->msgsize = 0;

	/* continue processing */
	return SMFIS_CONTINUE;
}

static sfsistat mlfi_cleanup(SMFICTX * ctx)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);
	struct rcptNode *p;
	struct rcptNode *node;

	if (priv == NULL)
		return SMFIS_CONTINUE;

	/* mlfi_envfrom() */
	if (priv->msgid != NULL) {
		free(priv->msgid);
		priv->msgid = NULL;
	}
	if (priv->envfrom != NULL) {
		free(priv->envfrom);
		priv->envfrom = NULL;
	}

	/* mlfi_envrcpt() */
	if (priv->rcpth != NULL) {
		p = priv->rcpth;
		while (p != NULL) {
			node = p;
			p = p->next;
			free(node->addr);
			free(node);
		}
		priv->rcpth = priv->rcptt = NULL;
	}

	/* mlfi_data() */
	if (priv->fname != NULL) {
		unlink(priv->fname);
		free(priv->fname);
		priv->fname = NULL;
	}
	if (priv->fp != NULL) {
		fclose(priv->fp);
		priv->fp = NULL;
	}

	/* continue processing */
	return SMFIS_CONTINUE;
}

static void daemonize(void)
{
	int i;

	config.daemon = 1;

	openlog(config.pname, LOG_PID, LOG_MAIL);

	i = fork();
	if (i == -1)
		exit(EX_UNAVAILABLE);
	if (i > 0)
		exit(0);

	setsid();
	if (chdir("/") != 0)
		exit(EX_UNAVAILABLE);

	for (i = getdtablesize(); i >= 0; i--)
		close(i);

	/* handle stdin, stdout, and stderr */
	i = open("/dev/null", O_RDWR);
	if (dup(i) == -1)
		exit(EX_UNAVAILABLE);
	if (dup(i) == -1)
		exit(EX_UNAVAILABLE);
}

static int drop_privs(const char *usr, const char *grp)
{
	struct passwd *pw = NULL;
	struct group *gr = NULL;

	/*
	 * there is only one thread yet, so it is safe to use non reentrant
	 * functions such as getpwent and getgrnam
	 */

	if ((usr == NULL) && (grp == NULL))
		return 0;

	/* return if we're not root */
	if (getuid()) {
		mlog(LOG_ERR, "Unable to set UID or GID");
		return -1;
	}

	/* GID */
	if (grp) {
		gr = getgrnam(grp);
		if (gr == NULL) {
			mlog(LOG_ERR, "Group \"%s\" not found", grp);
			return -1;
		}

		if (setgid(gr->gr_gid)) {
			mlog(LOG_ERR, "Unable to setgid to %d",
			     gr->gr_gid);
			return -1;
		}
	}

	/* UID */
	if (usr) {
		pw = getpwnam(usr);
		if (pw == NULL) {
			mlog(LOG_ERR, "User \"%s\" not found", usr);
			return -1;
		}

		if (setuid(pw->pw_uid)) {
			mlog(LOG_ERR, "Unable to setuid to %d",
			     pw->pw_uid);
			return -1;
		}
	}

	return 0;
}

static void pidf_create(const char *pidf)
{
	FILE *fp;

	fp = fopen(pidf, "w");
	if (fp == NULL) {
		mlog(LOG_ERR, "Unable to create PID file");
		return;
	}

	fprintf(fp, "%d\n", getpid());
	fclose(fp);
}

static void pidf_destroy(const char *pidf)
{
	unlink(pidf);
}

static int dn_check(const char *dname)
{
	if (strncmp(dname, "mail", 4) == 0)
		return 1;

	return 0;
}

static char *msg_create(const char *s1, const char *s2)
{
	char *p;
	size_t len;

	len = strlen(s1) + strlen(s2);
	p = malloc(len);
	if (p == NULL)
		return NULL;

	snprintf(p, len, "%s%s", s1, s2);

	return p;
}
