
/* $Id$ */

#include <signal.h>
#include <locale.h>

#include "nmap.h"
#include "NmapOps.h"
#include "utils.h"
#include "nmap_error.h"

#ifdef MTRACE
#include "mcheck.h"
#endif

#ifdef __amigaos__
#include <proto/exec.h>
#include <proto/dos.h>
#include "nmap_amigaos.h"
struct Library *SocketBase = NULL, *MiamiBase = NULL, *MiamiBPFBase = NULL, *MiamiPCapBase = NULL;
static const char ver[] = "$VER:" NMAP_NAME " v"NMAP_VERSION " [Amiga.sf]";

static void CloseLibs(void) {
  if (MiamiPCapBase ) CloseLibrary( MiamiPCapBase );
  if (MiamiBPFBase  ) CloseLibrary(  MiamiBPFBase );
  if ( SocketBase   ) CloseLibrary(   SocketBase  );
  if (  MiamiBase   ) CloseLibrary(   MiamiBase   );
}

static BOOL OpenLibs(void) {
 if(!(    MiamiBase = OpenLibrary(MIAMINAME,21))) return FALSE;
 if(!(   SocketBase = OpenLibrary("bsdsocket.library", 4))) return FALSE;
 if(!( MiamiBPFBase = OpenLibrary(MIAMIBPFNAME,3))) return FALSE;
 if(!(MiamiPCapBase = OpenLibrary(MIAMIPCAPNAME,5))) return FALSE;
 atexit(CloseLibs);
 return TRUE;
}
#endif

/* global options */
extern NmapOps o;  /* option structure */

extern void set_program_name(const char *name);

int main(int argc, char *argv[]) {
  /* The "real" main is nmap_main().  This function hijacks control at the
     beginning to do the following:
     1) Check the environment variable NMAP_ARGS.
     2) Check if Nmap was called with --resume.
     3) Resume a previous scan or just call nmap_main.
  */
  char command[2048];
  int myargc;
  char **myargv = NULL;
  char *cptr;
  int ret;
  int i;

  o.locale = strdup(setlocale(LC_CTYPE, NULL));
  set_program_name(argv[0]);

#ifdef __amigaos__
        if(!OpenLibs()) {
                error("Couldn't open TCP/IP Stack Library(s)!");
                exit(20);
        }
        MiamiBPFInit((struct Library *)MiamiBase, (struct Library *)SocketBase);
        MiamiPCapInit((struct Library *)MiamiBase, (struct Library *)SocketBase);
#endif

#ifdef MTRACE
  // This glibc extension enables memory tracing to detect memory
  // leaks, frees of unallocated memory, etc.
  // See http://www.gnu.org/manual/glibc-2.2.5/html_node/Allocation-Debugging.html#Allocation%20Debugging .
  // It only works if the environment variable MALLOC_TRACE is set to a file
  // which a memory usage log will be written to.  After the program quits
  // I can analyze the log via the command 'mtrace [binaryiran] [logfile]'
  // MTRACE should only be defined during debug sessions.
  mtrace();
#endif

  if ((cptr = getenv("NMAP_ARGS"))) {
    if (Snprintf(command, sizeof(command), "nmap %s", cptr) >= (int) sizeof(command)) {
        error("Warning: NMAP_ARGS variable is too long, truncated");
    }
    /* copy rest of command-line arguments */
    for (i = 1; i < argc && strlen(command) + strlen(argv[i]) + 1 < sizeof(command); i++) {
      strcat(command, " ");
      strcat(command, argv[i]);
    }
    myargc = arg_parse(command, &myargv);
    if (myargc < 1) {
      fatal("NMAP_ARGS variable could not be parsed");
    }
    ret = nmap_main(myargc, myargv);
    arg_parse_free(myargv);
    return ret;
  }

  if (argc == 3 && strcmp("--resume", argv[1]) == 0) {
    /* OK, they want to resume an aborted scan given the log file specified.
       Lets gather our state from the log file */
    if (gather_logfile_resumption_state(argv[2], &myargc, &myargv) == -1) {
      fatal("Cannot resume from (supposed) log file %s", argv[2]);
    }
    o.resuming = true;
    return nmap_main(myargc, myargv);
  }

  return nmap_main(argc, argv);
}
