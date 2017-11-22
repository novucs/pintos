/* size.c

   Displays size of files specified on command line. */

#include <stdio.h>
#include <syscall.h>

int
main (int argc, const char **argv)
{
  bool success = true;
  int i;

  for (i = 1; i < argc; i++)
    {
      int fd = open(argv[i]);

      if (fd == -1)
        {
          printf ("%s: File open failed\n", argv[i]);
          success = false;
          continue;
        }

      int size = filesize(fd);
      printf("Size of %s: %d", argv[i], size);
    }

  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
