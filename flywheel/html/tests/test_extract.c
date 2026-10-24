/** test_extract.c — extract readable text from real HTML. */

#include "../include/html.h"
#include "../src/runtime/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 20*1024*1024) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[got] = 0;
    *out_len = got;
    return buf;
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "corpus/html/example.com.html";
    size_t len;
    char *src = read_file(path, &len);
    if (!src) { printf("cannot read %s\n", path); return 1; }

    uint64_t t0 = plat_now_ns();
    html_document_t *doc = html_parse(src, len);
    uint64_t parse_ns = plat_now_ns() - t0;
    if (!doc) { printf("parse failed\n"); free(src); return 1; }

    /* Extract text */
    char *buf = (char *)malloc(1 << 22);   /* 4 MB */
    uint64_t t1 = plat_now_ns();
    int n = html_text_content(doc->root, buf, 1 << 22);
    uint64_t extract_ns = plat_now_ns() - t1;

    printf("=== %s ===\n", path);
    printf("  source:     %zu bytes\n", len);
    printf("  nodes:      %d\n", doc->n_nodes);
    printf("  parse time: %llu us\n", (unsigned long long)(parse_ns / 1000));
    printf("  extract:    %llu us\n", (unsigned long long)(extract_ns / 1000));
    printf("  text out:   %d bytes\n", n);
    printf("\n--- first 2000 bytes of text ---\n");
    int show = n < 2000 ? n : 2000;
    fwrite(buf, 1, (size_t)show, stdout);
    printf("\n--- end ---\n");

    free(buf);
    html_free(doc);
    free(src);
    return 0;
}
