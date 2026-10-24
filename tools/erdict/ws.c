/** ws.c — classify leading/trailing whitespace on a line.
 *
 * Fills these fields on erdict_line_t:
 *   lead_sp    number of leading spaces
 *   lead_tab   number of leading tabs
 *   trail      1 if the line ends with space or tab
 *   cr         1 if the line ended with \r (set by io.c)
 *   ws_ok      1 once computed
 */

#include "erdict.h"

void erdict_ws_classify(const erdict_file_t *f, erdict_line_t *l) {
    (void)f;
    if (!l || l->ws_ok) return;
    const char *p = l->p;
    size_t n = l->len;
    int sp = 0, tb = 0;
    size_t i = 0;
    for (; i < n; i++) {
        if (p[i] == ' ') sp++;
        else if (p[i] == '\t') tb++;
        else break;
    }
    l->lead_sp = sp;
    l->lead_tab = tb;
    l->trail = (n > 0 && (p[n-1] == ' ' || p[n-1] == '\t')) ? 1 : 0;
    l->ws_ok = 1;
}
