/* Plain driver so a fuzz target can run under gcc + ASAN without libFuzzer.
 * The target is chosen at COMPILE time: -DFZ_CTAP2 uses fz_ctap2, otherwise
 * fz_cbor. Reads each file argument and feeds it to the target.
 *   usage: driver <file>...
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef FZ_CTAP2
#define FZ_FN fz_ctap2
#else
#define FZ_FN fz_cbor
#endif

int FZ_FN(const unsigned char *data, size_t size);

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <file>...\n", argv[0]); return 2; }
    for (int a = 1; a < argc; a++) {
        FILE *f = fopen(argv[a], "rb");
        if (!f) { perror(argv[a]); continue; }
        if (fseek(f, 0, SEEK_END) != 0) { fclose(f); continue; }
        long n = ftell(f);
        if (n < 0 || n > (1 << 20)) { fclose(f); continue; }
        rewind(f);
        unsigned char *buf = (unsigned char *)malloc((size_t)n ? (size_t)n : 1);
        if (!buf) { fclose(f); return 2; }
        size_t got = fread(buf, 1, (size_t)n, f);
        fclose(f);
        int rc = FZ_FN(buf, got);
        free(buf);
        if (rc != 0) return rc;
    }
    return 0;
}
