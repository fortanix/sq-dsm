/* This example demonstrates how to use the packet parser from C.  It
 * also serves as a simple benchmark.  */

#define _GNU_SOURCE
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include <sequoia.h>

int
main (int argc, char **argv)
{
  struct stat st;
  int fd;
  uint8_t *b;
  sq_status_t rc;
  sq_error_t err;
  sq_context_t ctx;
  sq_packet_parser_result_t ppr;
  sq_packet_parser_t pp;

  if (argc != 2)
    error (1, 0, "Usage: %s <file>", argv[0]);

  ctx = sq_context_new ("org.sequoia-pgp.example", &err);
  if (ctx == NULL)
    error (1, 0, "Initializing sequoia failed: %s",
           sq_error_string (err));

  if (stat (argv[1], &st))
    error (1, errno, "%s", argv[1]);

  fd = open (argv[1], O_RDONLY);
  if (fd == -1)
    error (1, errno, "%s", argv[1]);

  b = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  close (fd);
  if (b == MAP_FAILED)
    error (1, errno, "mmap");

  size_t n = 0;
  time_t start = time (NULL);
  time_t elapsed;
  size_t tens_of_s = 0;

  ppr = sq_packet_parser_from_bytes (ctx, b, st.st_size);
  while (ppr && (pp = sq_packet_parser_result_packet_parser (ppr)))
    {
      // Get a reference to the packet that is currently being parsed.
      sq_packet_t p = sq_packet_parser_packet (pp);

      if (sq_packet_tag(p) == SQ_TAG_LITERAL)
        {
          // Stream the packet here.
        }

      // Finish parsing the current packet (returned in p), and read
      // the header of the next packet (returned in ppr).
      rc = sq_packet_parser_next (ctx, pp, &p, NULL, &ppr, NULL);
      if (rc)
	{
	  err = sq_context_last_error (ctx);
	  error (1, 0, "sq_packet_parser_from_bytes: %s",
                 sq_error_string (err));
	}

      // We now own p.  If we want, we can save it in some structure.
      // This would be useful when collecting PKESK packets.  Either
      // way, we need to free it when we are done.

      n += 1;

      sq_packet_free (p);

      elapsed = time (NULL) - start;
      if (elapsed % 10 == 0 && tens_of_s != elapsed / 10)
        {
          fprintf (stderr,
                   "Parsed %ld packets in %ld seconds, %.2f packets/s.\n",
                   n, elapsed, (double) n / (double) elapsed);
          fflush (stderr);
          tens_of_s = elapsed / 10;
        }
    }
  if (ppr == NULL)
    {
      err = sq_context_last_error (ctx);
      error (1, 0, "sq_packet_parser_from_bytes: %s", sq_error_string (err));
    }

  fprintf (stderr, "Parsed %ld packets in %ld seconds, %.2f packets/s.\n",
           n, elapsed, (double) n / (double) elapsed);

  sq_packet_parser_result_free (ppr);

  sq_context_free (ctx);
  munmap (b, st.st_size);
  return 0;
}
