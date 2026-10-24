/** os_sensors.c — portable CPU frequency + temperature reader. */

#include "os_sensors.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

/* ---- Linux/Android: /sys filesystem ---- */

#if defined(__linux__) || defined(__ANDROID__)

static int read_int_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int v = -1;
    if (fscanf(f, "%d", &v) != 1) v = -1;
    fclose(f);
    return v;
}

static int read_freq_khz_core0(void) {
    const char *paths[] = {
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        int khz = read_int_file(paths[i]);
        if (khz > 0) return khz;
    }
    return -1;
}

static int read_max_freq_khz_core0(void) {
    int khz = read_int_file("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
    if (khz > 0) return khz;
    return -1;
}

static int count_online_cpus(void) {
    int n = read_int_file("/sys/devices/system/cpu/online");
    if (n >= 0) {
        /* The format can be "0-7" — we can't parse that with fscanf easily.
         * Fall back to sysconf. */
    }
    /* Count cpuN directories. */
    DIR *d = opendir("/sys/devices/system/cpu");
    if (!d) return -1;
    int count = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == 'c' && e->d_name[1] == 'p' && e->d_name[2] == 'u') {
            /* skip the "cpufreq", "cpuidle" dirs — require digit after "cpu" */
            if (isdigit((unsigned char)e->d_name[3])) count++;
        }
    }
    closedir(d);
    return count > 0 ? count : -1;
}

/* Read the highest temperature among thermal zones. */
static int read_max_temp_c10(void) {
    DIR *d = opendir("/sys/class/thermal");
    if (!d) return -1;
    int maxt = -1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strncmp(e->d_name, "thermal_zone", 12) != 0) continue;
        char path[256];
        snprintf(path, sizeof(path), "/sys/class/thermal/%s/temp", e->d_name);
        int t = read_int_file(path);
        if (t > maxt) maxt = t;
    }
    closedir(d);
    /* Values are millidegrees in Linux. Convert to °C × 10. */
    return maxt > 0 ? maxt / 100 : -1;
}

void os_sensor_read(os_sensor_reading_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->temp_c10 = -1;

    int khz = read_freq_khz_core0();
    if (khz > 0) out->freq_mhz = khz / 1000;

    int maxkhz = read_max_freq_khz_core0();
    if (maxkhz > 0) out->freq_max_mhz = maxkhz / 1000;

    int ncpu = count_online_cpus();
    if (ncpu > 0) out->online_cpus = ncpu;

    out->temp_c10 = read_max_temp_c10();
    out->timestamp_ns = plat_now_ns();
}

#elif defined(__APPLE__)
  #include <sys/sysctl.h>

void os_sensor_read(os_sensor_reading_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->temp_c10 = -1;
    /* macOS: read CPU frequency via sysctl (in Hz on some versions) */
    uint64_t freq = 0;
    size_t sz = sizeof(freq);
    if (sysctlbyname("hw.cpufrequency", &freq, &sz, NULL, 0) == 0 && freq > 0) {
        out->freq_mhz = (int)(freq / 1000000);
    }
    out->timestamp_ns = plat_now_ns();
}

#elif defined(_WIN32)

void os_sensor_read(os_sensor_reading_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->temp_c10 = -1;
    /* On Windows, querying temp requires WMI and is slow.
     * Frequency: use QueryPerformanceFrequency (already used by platform.c). */
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    /* Not a real CPU frequency; leave freq_mhz = 0 to indicate "unknown". */
    out->timestamp_ns = plat_now_ns();
}

#else

void os_sensor_read(os_sensor_reading_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->temp_c10 = -1;
    out->timestamp_ns = plat_now_ns();
}

#endif

/* ---- public helpers ---- */

void os_sensor_print_state(const char *label) {
    os_sensor_reading_t s;
    os_sensor_read(&s);
    printf("  [%s] freq=%d MHz", label ? label : "state", s.freq_mhz);
    if (s.freq_max_mhz) printf("/max %d MHz", s.freq_max_mhz);
    if (s.temp_c10 >= 0) printf("  temp=%d.%d°C", s.temp_c10 / 10, s.temp_c10 % 10);
    if (s.online_cpus) printf("  cpus=%d", s.online_cpus);
    printf("\n");
}

uint64_t os_sensor_normalize_ns(uint64_t wall_ns, int freq_mhz, int reference_mhz) {
    if (freq_mhz <= 0 || reference_mhz <= 0) return wall_ns;
    /* If measured at 1000 MHz and reference is 2000 MHz, cost is halved. */
    return (wall_ns * (uint64_t)freq_mhz) / (uint64_t)reference_mhz;
}
