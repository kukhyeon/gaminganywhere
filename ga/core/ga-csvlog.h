#ifndef __GA_CSVLOG_H__
#define __GA_CSVLOG_H__

#include <float.h>
#include <limits.h>
#include <stdio.h>

#include "ga-common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ga_csvlog_side_s {
	GA_CSVLOG_SIDE_SERVER = 0,
	GA_CSVLOG_SIDE_CLIENT = 1
} ga_csvlog_side_t;

#define GA_CSVLOG_NONE_INT64 LLONG_MIN
#define GA_CSVLOG_NONE_DOUBLE DBL_MAX

typedef struct ga_csvlog_record_s {
	const char *component;
	const char *event;
	long long channel;
	long long seq;
	long long frame_no;
	long long frame_id;
	long long pts;
	long long size_bytes;
	const char *metric;
	double value;
	double aux_value;
	const char *note;
} ga_csvlog_record_t;

EXPORT void ga_csvlog_record_reset(ga_csvlog_record_t *record, const char *component, const char *event);
EXPORT int ga_csvlog_write(ga_csvlog_side_t side, const ga_csvlog_record_t *record);
EXPORT void ga_csvlog_close(ga_csvlog_side_t side);
EXPORT void ga_csvlog_close_all(void);

#ifdef __cplusplus
}
#endif

#endif
