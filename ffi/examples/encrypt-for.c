/* This example demonstrates how to use the low-level interface to
   encrypt a file.  */

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
  int use_armor = 1;
  sq_tpk_t tpk;
  sq_writer_t sink;
  sq_writer_stack_t writer = NULL;
  void *cipher = NULL;
  size_t cipher_bytes = 0;

  if (argc != 2)
    error (1, 0, "Usage: %s <keyfile> <plain >cipher", argv[0]);

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

  tpk = sq_tpk_from_bytes (ctx, b, st.st_size);
  if (tpk == NULL)
    {
      err = sq_context_last_error (ctx);
      error (1, 0, "sq_packet_parser_from_bytes: %s", sq_error_string (err));
    }

  sink = sq_writer_alloc (&cipher, &cipher_bytes);

  if (use_armor)
    sink = sq_armor_writer_new (ctx, sink, SQ_ARMOR_KIND_MESSAGE,
                                NULL, 0);

  writer = sq_writer_stack_wrap (sink);
  writer = sq_encryptor_new (ctx,
			     writer,
			     NULL, 0, /* no passwords */
			     &tpk, 1,
			     SQ_ENCRYPTION_MODE_FOR_TRANSPORT);
  if (writer == NULL)
    {
      err = sq_context_last_error (ctx);
      error (1, 0, "sq_encryptor_new: %s", sq_error_string (err));
    }

  writer = sq_literal_writer_new (ctx, writer);
  if (writer == NULL)
    {
      err = sq_context_last_error (ctx);
      error (1, 0, "sq_literal_writer_new: %s", sq_error_string (err));
    }

  size_t nread;
  uint8_t buf[4096];
  while ((nread = fread (buf, 1, sizeof buf, stdin)))
    {
      uint8_t *b = buf;
      while (nread)
	{
	  ssize_t written;
	  written = sq_writer_stack_write (ctx, writer, b, nread);
	  if (written < 0)
	    {
	      err = sq_context_last_error (ctx);
	      error (1, 0, "sq_writer_stack_write: %s", sq_error_string (err));
	    }
	  b += written;
	  nread -= written;
	}
    }

  rc = sq_writer_stack_finalize (ctx, writer);
  writer = NULL;
  if (rc)
    {
      err = sq_context_last_error (ctx);
      error (1, 0, "sq_writer_stack_write: %s", sq_error_string (err));
    }

  fwrite (cipher, 1, cipher_bytes, stdout);

  sq_context_free (ctx);
  munmap (b, st.st_size);
  return 0;
}
