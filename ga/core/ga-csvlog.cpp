/*
 * Centralized CSV logging for server/client metrics.
 */

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#ifndef WIN32
#include <sys/time.h>
#endif

#include "ga-csvlog.h"
#include "ga-conf.h"

typedef struct ga_csvlog_writer_s {
	const char *conf_key;
	FILE *fp;
	pthread_mutex_t mutex;
	int init_attempted;
} ga_csvlog_writer_t;

static ga_csvlog_writer_t g_csvlog_writers[] = {
	{ "save-server-csv-log", NULL, PTHREAD_MUTEX_INITIALIZER, 0 },
	{ "save-client-csv-log", NULL, PTHREAD_MUTEX_INITIALIZER, 0 }
};

static ga_csvlog_writer_t *
ga_csvlog_get_writer(ga_csvlog_side_t side) {
	switch(side) {
	case GA_CSVLOG_SIDE_SERVER:
		return &g_csvlog_writers[0];
	case GA_CSVLOG_SIDE_CLIENT:
		return &g_csvlog_writers[1];
	default:
		return NULL;
	}
}

static void
ga_csvlog_write_escaped(FILE *fp, const char *value) {
	const char *ptr = value;
	fputc('"', fp);
	while(ptr != NULL && *ptr != '\0') {
		if(*ptr == '"') {
			fputc('"', fp);
		}
		fputc(*ptr, fp);
		ptr++;
	}
	fputc('"', fp);
}

static void
ga_csvlog_write_int64(FILE *fp, long long value) {
	if(value != GA_CSVLOG_NONE_INT64) {
		fprintf(fp, "%lld", value);
	}
}

static void
ga_csvlog_write_double(FILE *fp, double value) {
	if(value != GA_CSVLOG_NONE_DOUBLE) {
		fprintf(fp, "%.6f", value);
	}
}

static int
ga_csvlog_open_locked(ga_csvlog_writer_t *writer) {
	char filename[1024];
	if(writer == NULL)
		return 0;
	if(writer->fp != NULL)
		return 1;
	if(writer->init_attempted != 0)
		return 0;
	writer->init_attempted = 1;
	if(ga_conf_readv(writer->conf_key, filename, sizeof(filename)) == NULL || filename[0] == '\0') {
		return 0;
	}
	writer->fp = ga_save_init_txt(filename);
	if(writer->fp == NULL) {
		return 0;
	}
	fprintf(writer->fp,
		"Timestamp,Component,Event,Channel,Seq,FrameNo,FrameID,PTS,SizeBytes,Metric,Value,AuxValue,Note\n");
	fflush(writer->fp);
	ga_error("csvlog: initialized %s -> %s\n", writer->conf_key, filename);
	return 1;
}

void
ga_csvlog_record_reset(ga_csvlog_record_t *record, const char *component, const char *event) {
	if(record == NULL)
		return;
	record->component = component;
	record->event = event;
	record->channel = GA_CSVLOG_NONE_INT64;
	record->seq = GA_CSVLOG_NONE_INT64;
	record->frame_no = GA_CSVLOG_NONE_INT64;
	record->frame_id = GA_CSVLOG_NONE_INT64;
	record->pts = GA_CSVLOG_NONE_INT64;
	record->size_bytes = GA_CSVLOG_NONE_INT64;
	record->metric = NULL;
	record->value = GA_CSVLOG_NONE_DOUBLE;
	record->aux_value = GA_CSVLOG_NONE_DOUBLE;
	record->note = NULL;
}

int
ga_csvlog_write(ga_csvlog_side_t side, const ga_csvlog_record_t *record) {
	ga_csvlog_writer_t *writer;
	struct timeval now;
	if(record == NULL)
		return -1;
	writer = ga_csvlog_get_writer(side);
	if(writer == NULL)
		return -1;
	pthread_mutex_lock(&writer->mutex);
	if(ga_csvlog_open_locked(writer) == 0) {
		pthread_mutex_unlock(&writer->mutex);
		return 0;
	}
	gettimeofday(&now, NULL);
	fprintf(writer->fp, "%lld.%06lld,",
		(long long) now.tv_sec, (long long) now.tv_usec);
	ga_csvlog_write_escaped(writer->fp, record->component);
	fputc(',', writer->fp);
	ga_csvlog_write_escaped(writer->fp, record->event);
	fputc(',', writer->fp);
	ga_csvlog_write_int64(writer->fp, record->channel);
	fputc(',', writer->fp);
	ga_csvlog_write_int64(writer->fp, record->seq);
	fputc(',', writer->fp);
	ga_csvlog_write_int64(writer->fp, record->frame_no);
	fputc(',', writer->fp);
	ga_csvlog_write_int64(writer->fp, record->frame_id);
	fputc(',', writer->fp);
	ga_csvlog_write_int64(writer->fp, record->pts);
	fputc(',', writer->fp);
	ga_csvlog_write_int64(writer->fp, record->size_bytes);
	fputc(',', writer->fp);
	ga_csvlog_write_escaped(writer->fp, record->metric);
	fputc(',', writer->fp);
	ga_csvlog_write_double(writer->fp, record->value);
	fputc(',', writer->fp);
	ga_csvlog_write_double(writer->fp, record->aux_value);
	fputc(',', writer->fp);
	ga_csvlog_write_escaped(writer->fp, record->note);
	fputc('\n', writer->fp);
	fflush(writer->fp);
	pthread_mutex_unlock(&writer->mutex);
	return 1;
}

void
ga_csvlog_close(ga_csvlog_side_t side) {
	ga_csvlog_writer_t *writer = ga_csvlog_get_writer(side);
	if(writer == NULL)
		return;
	pthread_mutex_lock(&writer->mutex);
	if(writer->fp != NULL) {
		ga_save_close(writer->fp);
		writer->fp = NULL;
	}
	writer->init_attempted = 0;
	pthread_mutex_unlock(&writer->mutex);
}

void
ga_csvlog_close_all(void) {
	ga_csvlog_close(GA_CSVLOG_SIDE_SERVER);
	ga_csvlog_close(GA_CSVLOG_SIDE_CLIENT);
}
