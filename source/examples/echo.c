#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  //msg("Executed exit 5\n");
  exit(5);
  while(1);
  int i;
  for (i = 0; i < argc; i++)
    printf ("%s ", argv[i]);
  printf ("\n");

  printf("Executed exit 1\n");
  return EXIT_SUCCESS;
}
