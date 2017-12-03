#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int i,j;
  for (i = 1; i < argc; i++)
    printf ("%s ", argv[i]);

  return EXIT_SUCCESS;
}
