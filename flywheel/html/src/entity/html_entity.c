/** html_entity.c — decode HTML entities. */

#include "html_entity.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

typedef struct { const char *name; int name_len; const char *utf8; } named_ent_t;

static const named_ent_t ENTITIES[] = {
    {"amp",3,"&"},{"lt",2,"<"},{"gt",2,">"},{"quot",4,"\""},{"apos",4,"'"},
    {"nbsp",4," "},{"copy",4,"\xc2\xa9"},{"reg",3,"\xc2\xae"},{"trade",5,"\xe2\x84\xa2"},
    {"mdash",5,"\xe2\x80\x94"},{"ndash",5,"\xe2\x80\x93"},{"hellip",6,"\xe2\x80\xa6"},
    {"laquo",5,"\xc2\xab"},{"raquo",5,"\xc2\xbb"},{"ldquo",5,"\xe2\x80\x9c"},
    {"rdquo",5,"\xe2\x80\x9d"},{"lsquo",5,"\xe2\x80\x98"},{"rsquo",5,"\xe2\x80\x99"},
    {"bull",4,"\xe2\x80\xa2"},{"middot",6,"\xc2\xb7"},{"sect",4,"\xc2\xa7"},
    {"para",4,"\xc2\xb6"},{"deg",3,"\xc2\xb0"},{"plusmn",6,"\xc2\xb1"},
    {"times",5,"\xc3\x97"},{"divide",6,"\xc3\xb7"},{"frac12",6,"\xc2\xbd"},
    {"frac14",6,"\xc2\xbc"},{"frac34",6,"\xc2\xbe"},{"sup2",4,"\xc2\xb2"},
    {"sup3",4,"\xc2\xb3"},{"euro",4,"\xe2\x82\xac"},{"pound",5,"\xc2\xa3"},
    {"yen",3,"\xc2\xa5"},{"cent",4,"\xc2\xa2"},{"larr",4,"\xe2\x86\x90"},
    {"rarr",4,"\xe2\x86\x92"},{"uarr",4,"\xe2\x86\x91"},{"darr",4,"\xe2\x86\x93"},
    {"harr",4,"\xe2\x86\x94"},{"alpha",5,"\xce\xb1"},{"beta",4,"\xce\xb2"},
    {"gamma",5,"\xce\xb3"},{"delta",5,"\xce\xb4"},{"pi",2,"\xcf\x80"},
    {"sigma",5,"\xcf\x83"},{"omega",5,"\xcf\x89"},
    {NULL,0,NULL}
};

static int utf8_encode(uint32_t cp, char *out) {
    if (cp < 0x80) { out[0] = (char)cp; return 1; }
    if (cp < 0x800) { out[0]=(char)(0xC0|(cp>>6)); out[1]=(char)(0x80|(cp&0x3F)); return 2; }
    if (cp < 0x10000) {
        out[0]=(char)(0xE0|(cp>>12)); out[1]=(char)(0x80|((cp>>6)&0x3F));
        out[2]=(char)(0x80|(cp&0x3F)); return 3;
    }
    if (cp < 0x110000) {
        out[0]=(char)(0xF0|(cp>>18)); out[1]=(char)(0x80|((cp>>12)&0x3F));
        out[2]=(char)(0x80|((cp>>6)&0x3F)); out[3]=(char)(0x80|(cp&0x3F)); return 4;
    }
    return 0;
}

int html_entity_decode(const char *in, int in_len, char *out, size_t cap) {
    size_t w = 0;
    int i = 0;
    while (i < in_len) {
        if (in[i] != '&') {
            if (w + 1 >= cap) break;
            out[w++] = in[i++];
            continue;
        }
        int end = i + 1;
        int limit = i + 32;
        if (limit > in_len) limit = in_len;
        while (end < limit && in[end] != ';') end++;
        if (end >= limit || in[end] != ';') {
            if (w + 1 >= cap) break;
            out[w++] = in[i++];
            continue;
        }
        int elen = end - i - 1;
        const char *ename = in + i + 1;
        if (elen >= 2 && ename[0] == '#') {
            uint32_t cp = 0;
            int ok = 0;
            if (ename[1] == 'x' || ename[1] == 'X') {
                for (int k = 2; k < elen; k++) {
                    char c = ename[k];
                    int v = -1;
                    if (c >= '0' && c <= '9') v = c - '0';
                    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
                    if (v < 0) { ok = 0; break; }
                    cp = cp * 16 + (uint32_t)v;
                    ok = 1;
                }
            } else {
                for (int k = 1; k < elen; k++) {
                    char c = ename[k];
                    if (c < '0' || c > '9') { ok = 0; break; }
                    cp = cp * 10 + (uint32_t)(c - '0');
                    ok = 1;
                }
            }
            if (ok && cp > 0) {
                char buf[4];
                int n = utf8_encode(cp, buf);
                if (w + (size_t)n >= cap) break;
                memcpy(out + w, buf, (size_t)n);
                w += (size_t)n;
                i = end + 1;
                continue;
            }
        }
        int matched = 0;
        for (int k = 0; ENTITIES[k].name; k++) {
            if (ENTITIES[k].name_len == elen &&
                memcmp(ENTITIES[k].name, ename, (size_t)elen) == 0) {
                size_t vl = strlen(ENTITIES[k].utf8);
                if (w + vl >= cap) { matched = 1; break; }
                memcpy(out + w, ENTITIES[k].utf8, vl);
                w += vl;
                i = end + 1;
                matched = 1;
                break;
            }
        }
        if (!matched) {
            if (w + 1 >= cap) break;
            out[w++] = in[i++];
        }
    }
    return (int)w;
}
