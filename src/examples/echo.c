#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int i,j;
  printf ("ECHO RAN\n");
  for (i = 0; i < argc; i++)
    printf ("%s ", argv[i]);
  printf ("ECHO RAN\n");

  return EXIT_SUCCESS;
}
