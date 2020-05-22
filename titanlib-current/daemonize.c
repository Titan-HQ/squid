/*
 * Do appropriate setup to daemonize a program - detach it from the parent
 * program and close all file descriptors
 *
 * This code is based on daemonize v1.5.1 by Brian M.Clapper, released under
 * BSD licence. See: http://www.clapper.org/software/daemonize
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "log.h"
#include "daemonize.h"
#include "global.h"

static int do_fork(){
   int status = 0;
   switch (fork()){
      case 0:
      /* This is the child to become the daemon. */
      break;

      case INVALID_:
      /* Failure */
         status =INVALID_;
      break;

      default:
      /* Parent: Exit. */
         _exit(0);
   }
   return status;
}

int daemonize(){
   struct rlimit rl;
   int i;
   int status = 0;
   if ((status = do_fork()) < 0 ){
      /* Fork once to go into the background. */
      //empty 
   } else if (setsid() < 0) {
      /* Create new session */
      status = -1;
   } else if ((status = do_fork()) < 0){
      /* Fork again to ensure that daemon never reacquires a control terminal. */
      //empty 
   } else {
      /* Get number of files allowed to open */
      if(getrlimit(RLIMIT_NOFILE, &rl) < 0)
      exit(EXIT_FAILURE);

      /* Close all open files */
      for(i = STDIN_FILENO; i < rl.rlim_max; ++i)
         close(i);

      /* Redirect stdout/err/in to /dev/null */
      open("/dev/null", O_RDWR);
      (void) dup(0);
      (void) dup(0);

      /* stderr is /dev/null, so not much point outputting log messages
      * there
      */
      titax_logsetlevel_stderr(LOG_FATAL);
   }
   return status;
}
