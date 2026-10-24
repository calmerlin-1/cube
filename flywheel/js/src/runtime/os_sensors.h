/** os_sensors.h — CPU frequency, temperature, online cores.
 * Portable: /sys on Linux/Android, sysctl on macOS, best-effort elsewhere. */

#ifndef FLYWHEEL_OS_SENSORS_H
#define FLYWHEEL_OS_SENSORS_H

#include <stdint.h>

typedef struct {
    int    freq_mhz;       /* current frequency of core 0; 0 if unknown */
    int    freq_max_mhz;   /* max frequency; 0 if unknown */
    int    temp_c10;       /* temperature × 10 (e.g. 425 = 42.5°C); -1 if unknown */
    int    online_cpus;    /* 0 if unknown */
    uint64_t timestamp_ns; /* when the reading was taken */
} os_sensor_reading_t;

/* Fill a sensor reading. Never crashes. Fields stay 0 or -1 if unavailable. */
void os_sensor_read(os_sensor_reading_t *out);

/* Print a one-line thermal/frequency state for the given label. */
void os_sensor_print_state(const char *label);

/* Normalize wall-clock nanoseconds to a reference frequency.
 * If measured freq is 0, returns wall_ns unchanged. */
uint64_t os_sensor_normalize_ns(uint64_t wall_ns, int freq_mhz, int reference_mhz);

#endif
