#define _GNU_SOURCE
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sequoia.h>

int
main (int argc, char **argv)
{
  struct stat st;
  int fd;
  uint8_t *b;
  sq_error_t err;
  sq_reader_t reader;
  sq_tpk_t tpk;

  if (argc != 2)
    error (1, 0, "Usage: %s <file>", argv[0]);

  if (stat (argv[1], &st))
    error (1, errno, "%s", argv[1]);

  fd = open (argv[1], O_RDONLY);
  if (fd == -1)
    error (1, errno, "%s", argv[1]);

  b = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (b == MAP_FAILED)
    error (1, errno, "mmap");

  reader = sq_reader_from_bytes (b, st.st_size);
  tpk = sq_tpk_from_reader (&err, reader);
  if (tpk == NULL)
    error (1, 0, "sq_tpk_from_reader: %s", sq_error_string (err));

  sq_tpk_dump (tpk);
  sq_tpk_free (tpk);
  sq_reader_free (reader);
  munmap (b, st.st_size);
  close (fd);
  return 0;
}
