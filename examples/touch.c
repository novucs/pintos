/* rm.c

   Creates files specified on command line. */

#include <stdio.h>
#include <syscall.h>

int
main (int argc, const char **argv)
{
  bool success = true;
  int i;

  for (i = 1; i < argc; i++)
    if (!create (argv[i], 8192))
      {
        printf ("%s: create failed\n", argv[i]);
        success = false;
      }
  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
