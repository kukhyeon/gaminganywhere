/*
 * Copyright (c) 2013-2014 Chun-Ying Huang
 *
 * This file is part of GamingAnywhere (GA).
 *
 * GA is free software; you can redistribute it and/or modify it
 * under the terms of the 3-clause BSD License as published by the
 * Free Software Foundation: http://directory.fsf.org/wiki/License:BSD_3Clause
 *
 * GA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the 3-clause BSD License along with GA;
 * if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <cstdint>
#include <time.h>
#include <stdlib.h>

#include "vsource.h"
#include "rtspconf.h"
#include "encoder-common.h"

#include "ga-common.h"
#include "ga-avcodec.h"
#include "ga-conf.h"
#include "ga-module.h"

#include "dpipe.h"

#include <map>
#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

# include <oping.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <x264.h>
#ifdef __cplusplus
}
#endif

static struct RTSPConf *rtspconf = NULL;

static int vencoder_initialized = 0;
static int vencoder_started = 0;
static pthread_t vencoder_tid[VIDEO_SOURCE_CHANNEL_MAX];
static pthread_mutex_t vencoder_reconf_mutex[VIDEO_SOURCE_CHANNEL_MAX];
static ga_ioctl_reconfigure_t vencoder_reconf[VIDEO_SOURCE_CHANNEL_MAX];
//// encoders for encoding
static x264_t* vencoder[VIDEO_SOURCE_CHANNEL_MAX];

// specific data for h.264
static char *_sps[VIDEO_SOURCE_CHANNEL_MAX];
static int _spslen[VIDEO_SOURCE_CHANNEL_MAX];
static char *_pps[VIDEO_SOURCE_CHANNEL_MAX];
static int _ppslen[VIDEO_SOURCE_CHANNEL_MAX];

// Feedback components
static std::map<uint32_t, struct timeval> frame_send_times;
static pthread_mutex_t time_map_mutex = PTHREAD_MUTEX_INITIALIZER;
static int feedback_sock = -1;
static pthread_t feedback_tid;
static int feedback_running = 0;
static FILE *savefp_feedback = NULL;
// ffffeddddbacckckkc

// ICMP Ping components
static pthread_t icmp_ping_tid;
static int icmp_ping_running = 0;
static FILE *savefp_icmp = NULL;

// ABR (Adaptive Bitrate) Components
static double current_udp_rtt = 0.0;   // ms
static double current_icmp_rtt = 0.0;  // ms
static pthread_mutex_t rtt_data_mutex = PTHREAD_MUTEX_INITIALIZER;
static int abr_enabled = 0;
static struct timeval vencoder_start_tv; // ⭐ 인코더 시작 시점 저장용

typedef struct ga_abr_config_s {
	int bitrateKbps;
	int bufsize;
	int framerate_n;
	int framerate_d;
} ga_abr_config_t;

static void *
feedback_threadproc(void *arg) {
	int s;
	struct sockaddr_in si_me, si_other;
	int slen = sizeof(si_other);
	uint32_t recv_frame_id;
#ifdef WIN32
	int rlen;
#else
	socklen_t rlen;
#endif

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		ga_error("feedback server: socket failed\n");
		return NULL;
	}
	
#ifdef WIN32
	DWORD timeout = 1000;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif

	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(55555);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);
	
	if (bind(s, (struct sockaddr*)&si_me, sizeof(si_me)) == -1) {
		ga_error("feedback server: bind failed\n");
#ifdef WIN32
		closesocket(s);
#else
		close(s);
#endif
		return NULL;
	}
	
	feedback_sock = s;
	ga_error("feedback server: started on port 55555\n");

	// Log file init
	char savefile_feedback[128];
	savefp_feedback = NULL;
	if (ga_conf_readbool("enable-feedback-log", 0) != 0) {
		if (ga_conf_readv("save-feedback-log", savefile_feedback, sizeof(savefile_feedback)) != NULL) {
			savefp_feedback = ga_save_init_txt(savefile_feedback);
			if (savefp_feedback) {
				ga_save_printf(savefp_feedback, "Timestamp, FrameID, RTT(us)\n");
			}
		}
	}

	while(feedback_running) {
		rlen = sizeof(si_other);
		if (recvfrom(s, (char*)&recv_frame_id, sizeof(recv_frame_id), 0, (struct sockaddr *) &si_other, &rlen) > 0) {
			pthread_mutex_lock(&time_map_mutex);
			if (frame_send_times.count(recv_frame_id)) {
				struct timeval now, sent_time;
				gettimeofday(&now, NULL);
				sent_time = frame_send_times[recv_frame_id];
				
				long long diff_us = tvdiff_us(&now, &sent_time);
				
				if (diff_us > 100000) { // 100ms
					ga_error("WARNING: Congestion Detected! RTT: %lld ms (Frame #%u)\n", diff_us/1000, recv_frame_id);
				}

				// ABR 데이터 업데이트
				pthread_mutex_lock(&rtt_data_mutex);
				if (recv_frame_id >= last_processed_frame_id) {
					current_udp_rtt = diff_us / 1000.0;
					last_processed_frame_id = recv_frame_id;
				}
				pthread_mutex_unlock(&rtt_data_mutex);
				
				// Save to log file
				if(savefp_feedback != NULL) {
					double rtime = (now.tv_sec - vencoder_start_tv.tv_sec) + (now.tv_usec - vencoder_start_tv.tv_usec) / 1000000.0;
					ga_save_printf(savefp_feedback, "%.6f, %u, %lld\n", rtime, recv_frame_id, diff_us);
				}

				frame_send_times.erase(recv_frame_id);
			}
			if(frame_send_times.size() > 1000) {
				frame_send_times.erase(frame_send_times.begin());
			}
			pthread_mutex_unlock(&time_map_mutex);
		}
	}
	
	if(savefp_feedback != NULL) {
		ga_save_close(savefp_feedback);
		savefp_feedback = NULL;
	}

#ifdef WIN32
	closesocket(s);
#else
	close(s);
#endif
	return NULL;
}

//#define	SAVEENC	"save.264"
#ifdef SAVEENC
static FILE *fsaveenc = NULL;
#endif

// Frame index tracking for debugging,claude  
static uint32_t sequential_frame_counter = 0;  // ⭐ 순차 카운터
static uint32_t random_seed = 0;               // ⭐ 난수 시드
static void *savefp_frameid = NULL;            // ⭐ 프레임 ID 로그 파일
static void *savefp_framesize = NULL;          // ⭐ 프레임 크기 로그 파일
static void *savefp_fps = NULL;                // ⭐ Frame Count 로그 파일 (추가)

static int
vencoder_deinit(void *arg) {
	int iid;
#ifdef SAVEENC
	if(fsaveenc != NULL) {
		fclose(fsaveenc);
		fsaveenc = NULL;
	}
#endif
	// ⭐ 로그 파일들 정리
	if(savefp_frameid != NULL) {
		ga_save_close((FILE*)savefp_frameid);
		savefp_frameid = NULL;
	}
	if(savefp_framesize != NULL) {
		ga_save_close((FILE*)savefp_framesize);
		savefp_framesize = NULL;
	}
	if(savefp_fps != NULL) {
		ga_save_close((FILE*)savefp_fps);
		savefp_fps = NULL;
	}
	
	for(iid = 0; iid < video_source_channels(); iid++) {
		if(_sps[iid] != NULL)
			free(_sps[iid]);
		if(_pps[iid] != NULL)
			free(_pps[iid]);
		if(vencoder[iid] != NULL)
			x264_encoder_close(vencoder[iid]);
		pthread_mutex_destroy(&vencoder_reconf_mutex[iid]);
		vencoder[iid] = NULL;
	}
	bzero(_sps, sizeof(_sps));
	bzero(_pps, sizeof(_pps));
	bzero(_spslen, sizeof(_spslen));
	bzero(_ppslen, sizeof(_ppslen));
	vencoder_initialized = 0;
	ga_error("video encoder: deinitialized.\n");
	return 0;
}

static int /* XXX: we need this because many GA config values are in bits, not Kbits */
ga_x264_param_parse_bit(x264_param_t *params, const char *name, const char *bitvalue) {
	int v = strtol(bitvalue, NULL, 0);
	char kbit[64];
	snprintf(kbit, sizeof(kbit), "%d", v / 1000);
	return x264_param_parse(params, name, kbit);
}

static int
vencoder_init(void *arg) {
	int iid;
	char *pipefmt = (char*) arg;
	struct RTSPConf *rtspconf = rtspconf_global();
	char profile[16], preset[16], tune[16];
	char x264params[1024];
	char tmpbuf[64];
	//
	if(rtspconf == NULL) {
		ga_error("video encoder: no configuration found\n");
		return -1;
	}
	if(vencoder_initialized != 0)
		return 0;
	//
	// ⭐ 기준 시간 동기화 (global start time 사용)
	vencoder_start_tv = *ga_get_start_time();

	for(iid = 0; iid < video_source_channels(); iid++) {
		char pipename[64];
		int outputW, outputH;
		dpipe_t *pipe;
		x264_param_t params;
		//
		_sps[iid] = _pps[iid] = NULL;
		_spslen[iid] = _ppslen[iid] = 0;
		pthread_mutex_init(&vencoder_reconf_mutex[iid], NULL);
		vencoder_reconf[iid].id = -1;
		//
		snprintf(pipename, sizeof(pipename), pipefmt, iid);
		outputW = video_source_out_width(iid);
		outputH = video_source_out_height(iid);
		if(outputW % 4 != 0 || outputH % 4 != 0) {
			ga_error("video encoder: unsupported resolutin %dx%d\n", outputW, outputH);
			goto init_failed;
		}
		if((pipe = dpipe_lookup(pipename)) == NULL) {
			ga_error("video encoder: pipe %s is not found\n", pipename);
			goto init_failed;
		}
		ga_error("video encoder: video source #%d from '%s' (%dx%d).\n",
			iid, pipe->name, outputW, outputH, iid);
		//
		bzero(&params, sizeof(params));
		x264_param_default(&params);
		// fill params
		preset[0] = tune[0] = '\0';
		ga_conf_mapreadv("video-specific", "preset", preset, sizeof(preset));
		ga_conf_mapreadv("video-specific", "tune", tune, sizeof(tune));
		if(preset[0] != '\0' || tune[0] != '\0') {
			if(x264_param_default_preset(&params, preset, tune) < 0) {
				ga_error("video encoder: bad x264 preset=%s; tune=%s\n", preset, tune);
				goto init_failed;
			} else {
				ga_error("video encoder: x264 preset=%s; tune=%s\n", preset, tune); 
			}
		}
		//
		if(ga_conf_mapreadv("video-specific", "b", tmpbuf, sizeof(tmpbuf)) != NULL)
			ga_x264_param_parse_bit(&params, "bitrate", tmpbuf);
		if(ga_conf_mapreadv("video-specific", "crf", tmpbuf, sizeof(tmpbuf)) != NULL)
			x264_param_parse(&params, "crf", tmpbuf);
		if(ga_conf_mapreadv("video-specific", "vbv-init", tmpbuf, sizeof(tmpbuf)) != NULL)
			x264_param_parse(&params, "vbv-init", tmpbuf);
		if(ga_conf_mapreadv("video-specific", "maxrate", tmpbuf, sizeof(tmpbuf)) != NULL)
			ga_x264_param_parse_bit(&params, "vbv-maxrate", tmpbuf);
		if(ga_conf_mapreadv("video-specific", "bufsize", tmpbuf, sizeof(tmpbuf)) != NULL)
			ga_x264_param_parse_bit(&params, "vbv-bufsize", tmpbuf);
		if(ga_conf_mapreadv("video-specific", "refs", tmpbuf, sizeof(tmpbuf)) != NULL)
			x264_param_parse(&params, "ref", tmpbuf);
		if(ga_conf_mapreadv("video-specific", "me_method", tmpbuf, sizeof(tmpbuf)) != NULL)
			x264_param_parse(&params, "me", tmpbuf);
		if(ga_conf_mapreadv("video-specific", "me_range", tmpbuf, sizeof(tmpbuf)) != NULL)
			x264_param_parse(&params, "merange", tmpbuf);
		if(ga_conf_mapreadv("video-specific", "g", tmpbuf, sizeof(tmpbuf)) != NULL)
			x264_param_parse(&params, "keyint", tmpbuf);
		if(ga_conf_mapreadv("video-specific", "intra-refresh", tmpbuf, sizeof(tmpbuf)) != NULL)
			x264_param_parse(&params, "intra-refresh", tmpbuf);
		//
		x264_param_parse(&params, "bframes", "0");
		x264_param_apply_fastfirstpass(&params);
		if(ga_conf_mapreadv("video-specific", "profile", profile, sizeof(profile)) != NULL) {
			if(x264_param_apply_profile(&params, profile) < 0) {
				ga_error("video encoder: x264 - bad profile %s\n", profile);
				goto init_failed;
			}
		}
		//
		if(ga_conf_readv("video-fps", tmpbuf, sizeof(tmpbuf)) != NULL)
			x264_param_parse(&params, "fps", tmpbuf);
		if(ga_conf_mapreadv("video-specific", "threads", tmpbuf, sizeof(tmpbuf)) != NULL)
			x264_param_parse(&params, "threads", tmpbuf);
		if(ga_conf_mapreadv("video-specific", "slices", tmpbuf, sizeof(tmpbuf)) != NULL)
			x264_param_parse(&params, "slices", tmpbuf);
		//
		params.i_log_level = X264_LOG_INFO;
		params.i_csp = X264_CSP_I420;
		params.i_width  = outputW;
		params.i_height = outputH;
		params.vui.b_fullrange = 1;
		params.b_repeat_headers = 1;
		params.b_annexb = 1;
		// handle x264-params
		if(ga_conf_mapreadv("video-specific", "x264-params", x264params, sizeof(x264params)) != NULL) {
			char *saveptr, *value;
			char *name = strtok_r(x264params, ":", &saveptr);
			while(name != NULL) {
				if((value = strchr(name, '=')) != NULL) {
					*value++ = '\0';
				}
				if(x264_param_parse(&params, name, value) < 0) {
					ga_error("video encoder: warning - bad x264 param [%s=%s]\n", name, value);
				}
				name = strtok_r(NULL, ":", &saveptr);
			}
		}
		//
		vencoder[iid] = x264_encoder_open(&params);
		if(vencoder[iid] == NULL)
			goto init_failed;
		ga_error("video encoder: opened! bitrate=%dKbps; me_method=%d; me_range=%d; refs=%d; g=%d; intra-refresh=%d; width=%d; height=%d; crop=%d,%d,%d,%d; threads=%d; slices=%d; repeat-hdr=%d; annexb=%d\n",
			params.rc.i_bitrate,
			params.analyse.i_me_method, params.analyse.i_me_range,
			params.i_frame_reference,
			params.i_keyint_max,
			params.b_intra_refresh,
			params.i_width, params.i_height,
			params.crop_rect.i_left, params.crop_rect.i_top,
			params.crop_rect.i_right, params.crop_rect.i_bottom,
			params.i_threads, params.i_slice_count,
			params.b_repeat_headers, params.b_annexb);
	}
#ifdef SAVEENC
	fsaveenc = fopen(SAVEENC, "wb");
#endif
	vencoder_initialized = 1;
	ga_error("video encoder: initialized.\n");
	return 0;
init_failed:
	vencoder_deinit(NULL);
	return -1;
}

static int
vencoder_reconfigure(int iid) {
	int ret = 0;
	x264_param_t params;
	x264_t *encoder = vencoder[iid];
	ga_ioctl_reconfigure_t *reconf = &vencoder_reconf[iid];
	int doit = 0;

	// 수동(ioctl) Reconfigure 처리
	pthread_mutex_lock(&vencoder_reconf_mutex[iid]);
	if(vencoder_reconf[iid].id >= 0) {
		x264_encoder_parameters(encoder, &params);
		if(reconf->crf > 0) {
			params.rc.f_rf_constant = 1.0 * reconf->crf;
			doit++;
		}
		if(reconf->framerate_n > 0) {
			params.i_fps_num = reconf->framerate_n;
			params.i_fps_den = reconf->framerate_d > 0 ? reconf->framerate_d : 1;
			doit++;
		}
		if(reconf->bitrateKbps > 0) {
			// XXX: do not use x264_param_parse("bitrate"), it switches mode to ABR
			// - although mode switching may be not allowed
			params.rc.i_bitrate = reconf->bitrateKbps;
			params.rc.i_vbv_max_bitrate = reconf->bitrateKbps;
			doit++;
		}
		if(reconf->bufsize > 0) {
			params.rc.i_vbv_buffer_size = reconf->bufsize;
			doit++;
		}
		//
		if(doit > 0) {
			if(x264_encoder_reconfig(encoder, &params) < 0) {
				ga_error("video encoder: reconfigure failed. crf=%d; framerate=%d/%d; bitrate=%d; bufsize=%d.\n",
						reconf->crf,
						reconf->framerate_n, reconf->framerate_d,
						reconf->bitrateKbps,
						reconf->bufsize);
				ret = -1;
			} else {
				ga_error("video encoder: reconfigured. crf=%.2f; framerate=%d/%d; bitrate=%d/%dKbps; bufsize=%dKbit.\n",
						params.rc.f_rf_constant,
						params.i_fps_num, params.i_fps_den,
						params.rc.i_bitrate, params.rc.i_vbv_max_bitrate,
						params.rc.i_vbv_buffer_size);
			}
		}
		reconf->id = -1;
	}
	pthread_mutex_unlock(&vencoder_reconf_mutex[iid]);
	return ret;
}

static void *
vencoder_threadproc(void *arg) {
	// arg is pointer to source pipename
	int iid, outputW, outputH;
	vsource_frame_t *frame = NULL;
	char *pipename = (char*) arg;
	dpipe_t *pipe = dpipe_lookup(pipename);
	dpipe_buffer_t *data = NULL;
	x264_t *encoder = NULL;
	//
	long long basePts = -1LL, newpts = 0LL, pts = -1LL, ptsSync = 0LL;
	//
	unsigned char *pktbuf = NULL;
	int pktbufsize = 0, pktbufmax = 0;
	int video_written = 0;
	int64_t x264_pts = 0;
	
	// Frame count logging variables
	int frame_interval_count = 0;
	long long byte_interval_count = 0; // ⭐ 추가: 1초당 누적 전송 바이트 수
	struct timeval last_log_tv, current_log_tv;
	gettimeofday(&last_log_tv, NULL);

	// ⭐ 프레임 ID 로그 파일 초기화 (프로그램 시작 시 한 번만)
	if (savefp_frameid == NULL) {
		if (ga_conf_readbool("enable-frame-id-log", 0) != 0) {
			char savefile_frameid[128];
			if(ga_conf_readv("save-frame-id-timestamp", savefile_frameid, sizeof(savefile_frameid)) != NULL) {
				savefp_frameid = ga_save_init_txt(savefile_frameid);
				ga_error("SERVER: Frame ID log file initialized: %s\n", savefile_frameid);
			}
		}
	}
	
	// ⭐ 프레임 크기 로그 파일 초기화 (프로그램 시작 시 한 번만)
	if (savefp_framesize == NULL) {
		if (ga_conf_readbool("enable-frame-size-log", 0) != 0) {
			char savefile_framesize[128];
			if(ga_conf_readv("save-frame-size-log", savefile_framesize, sizeof(savefile_framesize)) != NULL) {
				savefp_framesize = ga_save_init_txt(savefile_framesize);
				ga_error("SERVER: Frame size log file initialized: %s\n", savefile_framesize);
			}
		}
	}
	
	// ⭐ FPS 로그 파일 초기화 (프로그램 시작 시 한 번만)
	if (savefp_fps == NULL) {
		if (ga_conf_readbool("enable-fps-log", 0) != 0) {
			char savefile_fps[128];
			if(ga_conf_readv("save-fps-log", savefile_fps, sizeof(savefile_fps)) != NULL) {
				savefp_fps = ga_save_init_txt(savefile_fps);
				if(savefp_fps) {
					ga_save_printf((FILE*)savefp_fps, "Timestamp, FrameCount, BytesSent\n");
					ga_error("SERVER: Frame count log file initialized: %s\n", savefile_fps);
				}
			}
		}
	}
	
	// ⭐ 난수 시드 초기화 (프로그램 시작 시 한 번만)
	if (random_seed == 0) {
		random_seed = (uint32_t)time(NULL);
		srand(random_seed);
		ga_error("SERVER: Random seed initialized: 0x%08X\n", random_seed);
	}
	//
	if(pipe == NULL) {
		ga_error("video encoder: invalid pipeline specified (%s).\n", pipename);
		goto video_quit;
	}
	//
	rtspconf = rtspconf_global();
	// init variables
	iid = pipe->channel_id;
	encoder = vencoder[iid];
	//
	outputW = video_source_out_width(iid);
	outputH = video_source_out_height(iid);
	pktbufmax = outputW * outputH * 2 + 4;  // +4 bytes for frame index header
	if((pktbuf = (unsigned char*) malloc(pktbufmax)) == NULL) {
		ga_error("video encoder: allocate memory failed.\n");
		goto video_quit;
	}
	// start encoding
	ga_error("video encoding started: tid=%ld %dx%d@%dfps.\n",
		ga_gettid(),
		outputW, outputH, rtspconf->video_fps);
	//
	while(vencoder_started != 0 && encoder_running() > 0) {
		x264_picture_t pic_in, pic_out = {0};
		x264_nal_t *nal;
		int i, size, nnal;
		struct timeval tv;
		struct timespec to;
		gettimeofday(&tv, NULL);
		// need reconfigure?
		vencoder_reconfigure(iid);
		// wait for notification
		to.tv_sec = tv.tv_sec+1;
		to.tv_nsec = tv.tv_usec * 1000;
		data = dpipe_load(pipe, &to);
		if(data == NULL) {
			ga_error("viedo encoder: image source timed out.\n");
			continue;
		}
		frame = (vsource_frame_t*) data->pointer;
		// handle pts
		if(basePts == -1LL) {
			basePts = frame->imgpts;
			ptsSync = encoder_pts_sync(rtspconf->video_fps);
			newpts = ptsSync;
		} else {
			newpts = ptsSync + frame->imgpts - basePts;
		}
		//
		x264_picture_init(&pic_in);
		//
		pic_in.img.i_csp = X264_CSP_I420;
		pic_in.img.i_plane = 3;
		pic_in.img.i_stride[0] = frame->linesize[0];
		pic_in.img.i_stride[1] = frame->linesize[1];
		pic_in.img.i_stride[2] = frame->linesize[2];
		pic_in.img.plane[0] = frame->imgbuf;
		pic_in.img.plane[1] = pic_in.img.plane[0] + outputW*outputH;
		pic_in.img.plane[2] = pic_in.img.plane[1] + ((outputW * outputH) >> 2);
		// pts must be monotonically increasing
		if(newpts > pts) {
			pts = newpts;
		} else {
			pts++;
		}
		//pic_in.i_pts = pts;
		pic_in.i_pts = x264_pts++;
		// encode
		if((size = x264_encoder_encode(encoder, &nal, &nnal, &pic_in, &pic_out)) < 0) {
			ga_error("video encoder: encode failed, err = %d\n", size);
			dpipe_put(pipe, data);
			break;
		}
		dpipe_put(pipe, data);
		// encode
		if(size > 0) {
			AVPacket pkt;
#if 1
			av_init_packet(&pkt);
			pkt.pts = pic_in.i_pts;
			pkt.stream_index = 0;
			
			// concatenate nals
			pktbufsize = 0;
			for(i = 0; i < nnal; i++) {
				if(pktbufsize + nal[i].i_payload > pktbufmax) {
					ga_error("video encoder: nal dropped (%d < %d).\n", i+1, nnal);
					break;
				}
				bcopy(nal[i].p_payload, pktbuf + pktbufsize, nal[i].i_payload);
				pktbufsize += nal[i].i_payload;
			}
			pkt.size = pktbufsize;
			pkt.data = pktbuf;
			
			// ⭐ 순차번호 + 작은 난수 기반 고유 프레임 ID 생성
			uint32_t current_frame_number = sequential_frame_counter++;
			u_int32_t frameIndex = (current_frame_number << 8) | (rand() & 0xFF);  // 상위 24비트: 순차번호, 하위 8비트: 난수
			
			// Record send time for feedback
			pthread_mutex_lock(&time_map_mutex);
			struct timeval now;
			gettimeofday(&now, NULL);
			frame_send_times[frameIndex] = now;
			if(frame_send_times.size() > 1000) {
				frame_send_times.erase(frame_send_times.begin());
			}
			pthread_mutex_unlock(&time_map_mutex);
			
			// ⭐ 인코딩된 패킷 크기만 추적 (단순화)
			if(savefp_framesize != NULL) {
				struct timeval size_tv;
				gettimeofday(&size_tv, NULL);
				double rtime = (size_tv.tv_sec - vencoder_start_tv.tv_sec) + (size_tv.tv_usec - vencoder_start_tv.tv_usec) / 1000000.0;
				ga_save_printf((FILE*)savefp_framesize, 
					"Frame #%d | Encoded: %d bytes | Time: %u.%06u\n",
					frameIndex, pkt.size, size_tv.tv_sec, size_tv.tv_usec);
			}
			
			// 프레임 인덱스를 패킷 앞에 추가
			if(pkt.size + 4 <= pktbufmax) {
				// 기존 데이터를 4바이트 뒤로 이동
				memmove(pktbuf + 4, pktbuf, pkt.size);
				
				pktbuf[0] = (frameIndex >> 24) & 0xFF;  // 최상위 바이트
				pktbuf[1] = (frameIndex >> 16) & 0xFF;
				pktbuf[2] = (frameIndex >> 8) & 0xFF;
				pktbuf[3] = frameIndex & 0xFF;          // 최하위 바이트
				
				// 패킷 데이터와 크기 업데이트
				pkt.data = pktbuf;
				pkt.size += 4;
				
				// ⭐ 파일로 프레임 ID 저장 (깔끔한 로그)
				if(savefp_frameid != NULL) {
					struct timeval frameid_tv;
					gettimeofday(&frameid_tv, NULL);
					ga_save_printf((FILE*)savefp_frameid, "Frame #%04u → Random ID: %d (pts=%lld, time=%u.%06u)\n", 
						current_frame_number, (int32_t)frameIndex, pic_in.i_pts, frameid_tv.tv_sec, frameid_tv.tv_usec);
				}
				
				// ⭐ 서버 매칭 로그 (순차번호 → 난수 ID 매핑)
				ga_error("SERVER: Frame #%04u → Random ID: %d (pts=%lld, size=%d)\n", 
					current_frame_number, (int32_t)frameIndex, pic_in.i_pts, pkt.size);
			}
			
			// send the packet
			if(encoder_send_packet("video-encoder",
					iid/*rtspconf->video_id*/, &pkt,
					pkt.pts, NULL) < 0) {
				goto video_quit;
			}
			byte_interval_count += pkt.size; // ⭐ 추가: 전송 바이트 누적 (Method 1)
#ifdef SAVEENC
			if(fsaveenc != NULL)
				fwrite(pkt.data, sizeof(char), pkt.size, fsaveenc);
#endif
#else
			// handling special nals (type > 5)
			for(i = 0; i < nnal; i++) {
				unsigned char *ptr;
				int offset;
				if((ptr = ga_find_startcode(nal[i].p_payload, nal[i].p_payload + nal[i].i_payload, &offset))
				!= nal[i].p_payload) {
					ga_error("video encoder: no startcode found for nals\n");
					goto video_quit;
				}
				if((*(ptr+offset) & 0x1f) <= 5)
					break;
				av_init_packet(&pkt);
				pkt.pts = pic_in.i_pts;
				pkt.stream_index = 0;
				pkt.size = nal[i].i_payload;
				pkt.data = ptr;
				
				// 특별한 NAL들(SPS/PPS 등)에는 프레임 ID를 추가하지 않음
				// 이들은 메타데이터이므로 프레임 식별이 불필요
				
				if(encoder_send_packet("video-encoder",
					iid/*rtspconf->video_id*/, &pkt, pkt.pts, NULL) < 0) {
					goto video_quit;
				}
				byte_interval_count += pkt.size; // ⭐ 추가: 전송 바이트 누적 (Method 2 - SPS/PPS)
#ifdef SAVEENC
				if(fsaveenc != NULL)
					fwrite(pkt.data, sizeof(char), pkt.size, fsaveenc);
#endif
			}
			// handling video frame data
			pktbufsize = 0;
			for(; i < nnal; i++) {
				if(pktbufsize + nal[i].i_payload > pktbufmax) {
					ga_error("video encoder: nal dropped (%d < %d).\n", i+1, nnal);
					break;
				}
				bcopy(nal[i].p_payload, pktbuf + pktbufsize, nal[i].i_payload);
				pktbufsize += nal[i].i_payload;
			}
			if(pktbufsize > 0) {
				av_init_packet(&pkt);
				pkt.pts = pic_in.i_pts;
				pkt.stream_index = 0;
				pkt.size = pktbufsize;
				pkt.data = pktbuf;
				
				// ⭐ 순차번호 + 작은 난수 기반 고유 프레임 ID 생성
				uint32_t current_frame_number = sequential_frame_counter++;
				u_int32_t frameIndex = (current_frame_number << 8) | (rand() & 0xFF);  // 상위 24비트: 순차번호, 하위 8비트: 난수
				
				// ⭐ 인코딩된 패킷 크기만 추적 (단순화)
				if(savefp_framesize != NULL) {
					struct timeval size_tv;
					gettimeofday(&size_tv, NULL);
					ga_save_printf((FILE*)savefp_framesize, 
						"Frame #%04u | Encoded: %d bytes | Time: %u.%06u\n",
						current_frame_number, pkt.size, size_tv.tv_sec, size_tv.tv_usec);
				}
				
				// 프레임 인덱스를 패킷 앞에 추가
				if(pkt.size + 4 <= pktbufmax) {
					// 기존 데이터를 4바이트 뒤로 이동
					memmove(pktbuf + 4, pktbuf, pkt.size);
					
					pktbuf[0] = (frameIndex >> 24) & 0xFF;  // 최상위 바이트
					pktbuf[1] = (frameIndex >> 16) & 0xFF;
					pktbuf[2] = (frameIndex >> 8) & 0xFF;
					pktbuf[3] = frameIndex & 0xFF;          // 최하위 바이트
					
					// 패킷 데이터와 크기 업데이트
					pkt.data = pktbuf;
					pkt.size += 4;
					
					// ⭐ 파일로 프레임 ID 저장 (깔끔한 로그)
					if(savefp_frameid != NULL) {
						struct timeval frameid_tv;
						gettimeofday(&frameid_tv, NULL);
						ga_save_printf((FILE*)savefp_frameid, "Frame #%04u → Random ID: %d (pts=%lld, time=%u.%06u)\n", 
							current_frame_number, (int32_t)frameIndex, pic_in.i_pts, frameid_tv.tv_sec, frameid_tv.tv_usec);
					}
					
					// ⭐ 서버 매칭 로그 (순차번호 → 난수 ID 매핑)
					ga_error("SERVER: Frame #%04u → Random ID: %d (pts=%lld, size=%d)\n", 
						current_frame_number, (int32_t)frameIndex, pic_in.i_pts, pkt.size);
				}
				
				if(encoder_send_packet("video-encoder",
					iid/*rtspconf->video_id*/, &pkt, pkt.pts, NULL) < 0) {
					goto video_quit;
				}
				byte_interval_count += pkt.size; // ⭐ 추가: 전송 바이트 누적 (Method 2 - Video Frame)
#ifdef SAVEENC
				if(fsaveenc != NULL)
					fwrite(pkt.data, sizeof(char), pkt.size, fsaveenc);
#endif
			}
#endif
			// free unused side-data
			if(pkt.side_data_elems > 0) {
				int i;
				for (i = 0; i < pkt.side_data_elems; i++)
					av_free(pkt.side_data[i].data);
				av_freep(&pkt.side_data);
				pkt.side_data_elems = 0;
			}
			//
			if(video_written == 0) {
				video_written = 1;
				ga_error("first video frame written (pts=%lld)\n", pic_in.i_pts);
			}

			// Frame count logging (every 1 second)
			// 인코딩도 성공하고, 전송 함수 호출도 에러 없이 끝난 횟수
			frame_interval_count++;
			gettimeofday(&current_log_tv, NULL);
			long long log_diff_us = tvdiff_us(&current_log_tv, &last_log_tv);
			
			if (log_diff_us >= 1000000) { // 1 second
				if (savefp_fps != NULL) {
					double relative_time = (current_log_tv.tv_sec - vencoder_start_tv.tv_sec) + (current_log_tv.tv_usec - vencoder_start_tv.tv_usec) / 1000000.0;
					ga_save_printf((FILE*)savefp_fps, "%.6f, %d, %lld\n", 
						relative_time, 
						frame_interval_count, byte_interval_count);
				}
				
				// Reset counters
				frame_interval_count = 0;
				byte_interval_count = 0;
				last_log_tv = current_log_tv;
			}
		}
	}
	//
video_quit:
	if(pipe) {
		pipe = NULL;
	}
	if(pktbuf != NULL) {
		free(pktbuf);
	}
	pktbuf = NULL;
	//
	ga_error("video encoder: thread terminated (tid=%ld).\n", ga_gettid());
	//
	return NULL;
}

// RTT Server Logic
static int rtt_sock = -1;
static pthread_t rtt_tid;
static int rtt_running = 0;
static struct sockaddr_in rtt_client_addr;
static int rtt_client_known = 0;
static FILE *savefp_rtt = NULL;

#pragma pack(push, 1)
typedef struct {
	uint32_t seq;
	uint32_t sec;
	uint32_t usec;
} rtt_packet_t;
#pragma pack(pop)

static void *
rtt_server_threadproc(void *arg) {
	int s;
	struct sockaddr_in si_me, si_other;
	rtt_packet_t send_pkt, recv_pkt;
	uint32_t seq = 0;
#ifdef WIN32
	int rlen;
#else
	socklen_t rlen;
#endif

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		ga_error("RTT server: socket failed\n");
		return NULL;
	}
	
#ifdef WIN32
	DWORD timeout = 100;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 100000; // 100ms
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif

	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(55556); // RTT Port
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);
	
	if (bind(s, (struct sockaddr*)&si_me, sizeof(si_me)) == -1) {
		ga_error("RTT server: bind failed (port 55556)\n");
#ifdef WIN32
		closesocket(s);
#else
		close(s);
#endif
		return NULL;
	}
	
	rtt_sock = s;
	ga_error("RTT server: started on port 55556\n");
	
	// Log file init
	char savefile_rtt[128];
	if(ga_conf_readv("save-rtt-log", savefile_rtt, sizeof(savefile_rtt)) != NULL) {
		savefp_rtt = ga_save_init_txt(savefile_rtt);
		if(savefp_rtt) {
			ga_save_printf(savefp_rtt, "Time(s), Seq, RTT(ms)\n");
			ga_error("SERVER: RTT log file initialized: %s\n", savefile_rtt);
		}
	}

	struct timeval last_ping_time, now;
	gettimeofday(&last_ping_time, NULL);

	while(rtt_running) {
		rlen = sizeof(si_other);
		int recv_len = recvfrom(s, (char*)&recv_pkt, sizeof(recv_pkt), 0, (struct sockaddr *) &si_other, &rlen);
		
		if (recv_len > 0) {
			if (!rtt_client_known || 
				rtt_client_addr.sin_addr.s_addr != si_other.sin_addr.s_addr ||
				rtt_client_addr.sin_port != si_other.sin_port) {
				
				memcpy(&rtt_client_addr, &si_other, sizeof(si_other));
				rtt_client_known = 1;
				ga_error("RTT server: client detected at %s:%d\n", 
					inet_ntoa(rtt_client_addr.sin_addr), ntohs(rtt_client_addr.sin_port));
			}

			if (recv_len == sizeof(rtt_packet_t)) {
				gettimeofday(&now, NULL);
				struct timeval sent_tv;
				sent_tv.tv_sec = recv_pkt.sec;
				sent_tv.tv_usec = recv_pkt.usec;
				
				long long diff_us = tvdiff_us(&now, &sent_tv);
				if (diff_us >= 0 && diff_us < 10000000) {
					double rtt_ms = diff_us / 1000.0;
					if (savefp_rtt != NULL) {
						ga_save_printf(savefp_rtt, "%u.%06u, %u, %.3f\n", now.tv_sec, now.tv_usec, recv_pkt.seq, rtt_ms);
					}
				}
			}
		}

		gettimeofday(&now, NULL);
		if (rtt_client_known) {
			long long interval = tvdiff_us(&now, &last_ping_time); // return micro sec
			if (interval >= 50000) { // 0.5 sec (50ms)
				send_pkt.seq = seq++;
				send_pkt.sec = now.tv_sec;
				send_pkt.usec = now.tv_usec;
				
				sendto(s, (const char*)&send_pkt, sizeof(send_pkt), 0, (struct sockaddr*)&rtt_client_addr, sizeof(rtt_client_addr));
				last_ping_time = now;
			}
		} else {
			usleep(10000);
		}
	}

	if(savefp_rtt != NULL) {
		ga_save_close(savefp_rtt);
		savefp_rtt = NULL;
	}

#ifdef WIN32
	closesocket(s);
#else
	close(s);
#endif
	return NULL;
}

static void *
icmp_ping_threadproc(void *arg) {
	pingobj_t *ping;
	pingobj_iter_t *iter;
	const char *host = "client IP"; // Default host
	double timeout = 1.0;
	char savefile_icmp[128];

	if ((ping = ping_construct()) == NULL) {
		ga_error("ICMP Ping: construct failed\n");
		return NULL;
	}

	ping_setopt(ping, PING_OPT_TIMEOUT, &timeout);

	// In a real scenario, you might want to get the client's IP from rtspconf
	if (ping_host_add(ping, host) < 0) {
		ga_error("ICMP Ping: failed to add host %s\n", host);
		ping_destroy(ping);
		return NULL;
	}

	// Log file init
	if(ga_conf_readv("save-icmp-log", savefile_icmp, sizeof(savefile_icmp)) != NULL) {
		savefp_icmp = ga_save_init_txt(savefile_icmp);
		if(savefp_icmp) {
			ga_save_printf(savefp_icmp, "Time(s), RTT(ms)\n");
			ga_error("SERVER: ICMP log file initialized: %s\n", savefile_icmp);
		}
	}

	while(icmp_ping_running) {
		if (ping_send(ping) < 0) {
			// This might fail if permissions are not set (raw socket)
			ga_error("ICMP Ping: send failed (Check sudo/capabilities)\n");
			usleep(1000000); // Wait 1s on error
			continue;
		}

		for (iter = ping_iterator_get(ping); iter != NULL; iter = ping_iterator_next(iter)) {
			double latency = -1.0;
			size_t len = sizeof(latency);
			ping_iterator_get_info(iter, PING_INFO_LATENCY, &latency, &len);

			if (latency >= 0) {
				struct timeval now;
				gettimeofday(&now, NULL);
				
				if (savefp_icmp) {
					double rtime = (now.tv_sec - vencoder_start_tv.tv_sec) + (now.tv_usec - vencoder_start_tv.tv_usec) / 1000000.0;
					ga_save_printf(savefp_icmp, "%.6f, %.3f\n", rtime, latency);
				}

				if (latency > 100.0) {
					ga_error("WARNING: ICMP High Latency! RTT: %.2f ms\n", latency);
				}

				// ABR 데이터 업데이트
				pthread_mutex_lock(&rtt_data_mutex);
				current_icmp_rtt = latency;
				pthread_mutex_unlock(&rtt_data_mutex);
			}
		}
		usleep(100000); // 0.1s interval
	}

	if(savefp_icmp != NULL) {
		ga_save_close(savefp_icmp);
		savefp_icmp = NULL;
	}

	ping_destroy(ping);
	ga_error("ICMP Ping: thread terminated.\n");
	return NULL;
}

static int
vencoder_start(void *arg) {
	int iid;
	char *pipefmt = (char*) arg;
	char tmpbuf[16];
#define	MAXPARAMLEN	64
	static char pipename[VIDEO_SOURCE_CHANNEL_MAX][MAXPARAMLEN];
	if(vencoder_started != 0)
		return 0;
	vencoder_started = 1;

	// Start feedback thread
	feedback_running = 1;
	if(pthread_create(&feedback_tid, NULL, feedback_threadproc, NULL) != 0) {
		ga_error("video encoder: cannot create feedback thread\n");
	}

	// Start RTT thread (UDP) - Logic-based Activation
	rtt_running = 0;
	if (ga_conf_readv("enable-udp-rtt", tmpbuf, sizeof(tmpbuf)) != NULL && atoi(tmpbuf) != 0) {
		rtt_running = 1;
		rtt_client_known = 0;
		if(pthread_create(&rtt_tid, NULL, rtt_server_threadproc, NULL) != 0) {
			rtt_running = 0;
			ga_error("video encoder: cannot create RTT thread\n");
		}
	}

	// Start ICMP Ping thread - Logic-based Activation
	icmp_ping_running = 0;
	if (ga_conf_readv("enable-icmp-ping", tmpbuf, sizeof(tmpbuf)) != NULL && atoi(tmpbuf) != 0) {
		icmp_ping_running = 1;
		if(pthread_create(&icmp_ping_tid, NULL, icmp_ping_threadproc, NULL) != 0) {
			icmp_ping_running = 0;
			ga_error("video encoder: cannot create ICMP Ping thread\n");
		}
	}

	for(iid = 0; iid < video_source_channels(); iid++) {
		snprintf(pipename[iid], MAXPARAMLEN, pipefmt, iid);
		if(pthread_create(&vencoder_tid[iid], NULL, vencoder_threadproc, pipename[iid]) != 0) {
			vencoder_started = 0;
			ga_error("video encoder: create thread failed.\n");
			return -1;
		}
	}
	ga_error("video encdoer: all started (%d)\n", iid);
	return 0;
}

static int
vencoder_stop(void *arg) {
	int iid;
	void *ignored;
	if(vencoder_started == 0)
		return 0;
	vencoder_started = 0;

	// Stop feedback thread
	feedback_running = 0;
	pthread_join(feedback_tid, NULL);

	// Stop RTT thread (UDP)
	if (rtt_running) {
		rtt_running = 0;
		pthread_join(rtt_tid, NULL);
	}

	// Stop ICMP Ping thread
	if (icmp_ping_running) {
		icmp_ping_running = 0;
		pthread_join(icmp_ping_tid, NULL);
	}

	for(iid = 0; iid < video_source_channels(); iid++) {
		pthread_join(vencoder_tid[iid], &ignored);
	}
	ga_error("video encdoer: all stopped (%d)\n", iid);
	return 0;
}

static void *
vencoder_raw(void *arg, int *size) {
#if defined __APPLE__
	int64_t in = (int64_t) arg;
	int iid = (int) (in & 0xffffffffLL);
#else
	intptr_t in = (intptr_t)arg;
    	int iid = (int)in;
#endif
	if(vencoder_initialized == 0)
		return NULL;
	if(size)
		*size = sizeof(vencoder[iid]);
	return vencoder[iid];
}

static int
x264_reconfigure(ga_ioctl_reconfigure_t *reconf) {
	if(vencoder_started == 0 || encoder_running() == 0) {
		ga_error("video encoder: reconfigure - not running.\n");
		return 0;
	}
	pthread_mutex_lock(&vencoder_reconf_mutex[reconf->id]);
	bcopy(reconf, &vencoder_reconf[reconf->id], sizeof(ga_ioctl_reconfigure_t));
	pthread_mutex_unlock(&vencoder_reconf_mutex[reconf->id]);
	return 0;
}

static int
x264_get_sps_pps(int iid) {
	x264_nal_t *p_nal;
	int ret = 0;
	int i, i_nal;
	// alread obtained?
	if(_sps[iid] != NULL)
		return 0;
	//
	if(vencoder_initialized == 0)
		return GA_IOCTL_ERR_NOTINITIALIZED;
	if(x264_encoder_headers(vencoder[iid], &p_nal, &i_nal) < 0)
		return GA_IOCTL_ERR_NOTFOUND;
	for(i = 0; i < i_nal; i++) {
		if(p_nal[i].i_type == NAL_SPS) {
			if((_sps[iid] = (char*) malloc(p_nal[i].i_payload)) == NULL) {
				ret = GA_IOCTL_ERR_NOMEM;
				break;
			}
			bcopy(p_nal[i].p_payload, _sps[iid], p_nal[i].i_payload);
			_spslen[iid] = p_nal[i].i_payload;
		} else if(p_nal[i].i_type == NAL_PPS) {
			if((_pps[iid] = (char*) malloc(p_nal[i].i_payload)) == NULL) {
				ret = GA_IOCTL_ERR_NOMEM;
				break;
			}
			bcopy(p_nal[i].p_payload, _pps[iid], p_nal[i].i_payload);
			_ppslen[iid] = p_nal[i].i_payload;
		}
	}
	//
	if(_sps[iid] == NULL || _pps[iid] == NULL) {
		if(_sps[iid])	free(_sps[iid]);
		if(_pps[iid])	free(_pps[iid]);
		_sps[iid] = _pps[iid] = NULL;
		_spslen[iid] = _ppslen[iid] = 0;
	} else {
		ga_error("video encoder: found sps (%d bytes); pps (%d bytes)\n",
			_spslen[iid], _ppslen[iid]);
	}
	return ret;
}

static int
vencoder_ioctl(int command, int argsize, void *arg) {
	int ret = 0;
	ga_ioctl_buffer_t *buf = (ga_ioctl_buffer_t*) arg;
	//
	if(vencoder_initialized == 0)
		return GA_IOCTL_ERR_NOTINITIALIZED;
	//
	switch(command) {
	case GA_IOCTL_RECONFIGURE:
		if(argsize != sizeof(ga_ioctl_reconfigure_t))
			return GA_IOCTL_ERR_INVALID_ARGUMENT;
		x264_reconfigure((ga_ioctl_reconfigure_t*) arg);
		break;
	case GA_IOCTL_GETSPS:
		if(argsize != sizeof(ga_ioctl_buffer_t))
			return GA_IOCTL_ERR_INVALID_ARGUMENT;
		if(x264_get_sps_pps(buf->id) < 0)
			return GA_IOCTL_ERR_NOTFOUND;
		if(buf->size < _spslen[buf->id])
			return GA_IOCTL_ERR_BUFFERSIZE;
		buf->size = _spslen[buf->id];
		bcopy(_sps[buf->id], buf->ptr, buf->size);
		break;
	case GA_IOCTL_GETPPS:
		if(argsize != sizeof(ga_ioctl_buffer_t))
			return GA_IOCTL_ERR_INVALID_ARGUMENT;
		if(x264_get_sps_pps(buf->id) < 0)
			return GA_IOCTL_ERR_NOTFOUND;
		if(buf->size < _ppslen[buf->id])
			return GA_IOCTL_ERR_BUFFERSIZE;
		buf->size = _ppslen[buf->id];
		bcopy(_pps[buf->id], buf->ptr, buf->size);
		break;
	case GA_IOCTL_GET_NETWORK_STATUS:
		if(argsize != sizeof(ga_ioctl_network_status_t))
			return GA_IOCTL_ERR_INVALID_ARGUMENT;
		{
			ga_ioctl_network_status_t *net_stat = (ga_ioctl_network_status_t*) arg;
			pthread_mutex_lock(&rtt_data_mutex);
			net_stat->udp_rtt_ms = current_udp_rtt;
			net_stat->icmp_rtt_ms = current_icmp_rtt;
			pthread_mutex_unlock(&rtt_data_mutex);
		}
		break;
	default:
		ret = GA_IOCTL_ERR_NOTSUPPORTED;
		break;
	}
	return ret;
}

ga_module_t *
module_load() {
	static ga_module_t m;
	//
	bzero(&m, sizeof(m));
	m.type = GA_MODULE_TYPE_VENCODER;
	m.name = strdup("x264-video-encoder");
	m.mimetype = strdup("video/H264");
	m.init = vencoder_init;
	m.start = vencoder_start;
	//m.threadproc = vencoder_threadproc;
	m.stop = vencoder_stop;
	m.deinit = vencoder_deinit;
	//
	m.raw = vencoder_raw;
	m.ioctl = vencoder_ioctl;
	return &m;
}

