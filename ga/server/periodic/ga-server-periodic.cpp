/*
 * Copyright (c) 2013 Chun-Ying Huang
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
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include "ga-common.h"
#include "ga-conf.h"
#include "ga-module.h"
#include "rtspconf.h"
#include "controller.h"
#include "encoder-common.h"

////#define	TEST_RECONFIGURE

// image source pipeline:
//	vsource -- [vsource-%d] --> filter -- [filter-%d] --> encoder

// configurations:
static char *imagepipefmt = "video-%d";
static char *filterpipefmt = "filter-%d";
static char *imagepipe0 = "video-0";
static char *filterpipe0 = "filter-0";
static char *filter_param[] = { imagepipefmt, filterpipefmt };
static char *video_encoder_param = filterpipefmt;
static void *audio_encoder_param = NULL;

static struct gaRect *prect = NULL;
static struct gaRect rect;

static ga_module_t *m_vsource, *m_filter, *m_vencoder, *m_asource, *m_aencoder, *m_ctrl, *m_server;

int
load_modules() {
	if((m_vsource = ga_load_module("mod/vsource-desktop", "vsource_")) == NULL)
		return -1;
	if((m_filter = ga_load_module("mod/filter-rgb2yuv", "filter_RGB2YUV_")) == NULL)
		return -1;
	if((m_vencoder = ga_load_module("mod/encoder-x264", "vencoder_")) == NULL)
		return -1;
	if(ga_conf_readbool("enable-audio", 1) != 0) {
	//////////////////////////
#ifndef __APPLE__
	if((m_asource = ga_load_module("mod/asource-system", "asource_")) == NULL)
		return -1;
#endif
	if((m_aencoder = ga_load_module("mod/encoder-audio", "aencoder_")) == NULL)
		return -1;
	//////////////////////////
	}
	if((m_ctrl = ga_load_module("mod/ctrl-sdl", "sdlmsg_replay_")) == NULL)
		return -1;
	if((m_server = ga_load_module("mod/server-live555", "live_")) == NULL)
		return -1;
	return 0;
}

int
init_modules() {
	struct RTSPConf *conf = rtspconf_global();
	//static const char *filterpipe[] = { imagepipe0, filterpipe0 };
	if(conf->ctrlenable) {
		ga_init_single_module_or_quit("controller", m_ctrl, (void *) prect);
	}
	// controller server is built-in - no need to init
	// note the order of the two modules ...
	ga_init_single_module_or_quit("video-source", m_vsource, (void*) prect);
	ga_init_single_module_or_quit("filter", m_filter, (void*) filter_param);
	//
	ga_init_single_module_or_quit("video-encoder", m_vencoder, filterpipefmt);
	if(ga_conf_readbool("enable-audio", 1) != 0) {
	//////////////////////////
#ifndef __APPLE__
	ga_init_single_module_or_quit("audio-source", m_asource, NULL);
#endif
	ga_init_single_module_or_quit("audio-encoder", m_aencoder, NULL);
	//////////////////////////
	}
	//
	ga_init_single_module_or_quit("server-live555", m_server, NULL);
	//
	return 0;
}

int
run_modules() {
	struct RTSPConf *conf = rtspconf_global();
	static const char *filterpipe[] =  { imagepipe0, filterpipe0 };
	// controller server is built-in, but replay is a module
	if(conf->ctrlenable) {
		ga_run_single_module_or_quit("control server", ctrl_server_thread, conf);
		// XXX: safe to comment out?
		//ga_run_single_module_or_quit("control replayer", m_ctrl->threadproc, conf);
	}
	// video
	//ga_run_single_module_or_quit("image source", m_vsource->threadproc, (void*) imagepipefmt);
	if(m_vsource->start(prect) < 0)		exit(-1);
	//ga_run_single_module_or_quit("filter 0", m_filter->threadproc, (void*) filterpipe);
	if(m_filter->start(filter_param) < 0)	exit(-1);
	encoder_register_vencoder(m_vencoder, video_encoder_param);
	// audio
	if(ga_conf_readbool("enable-audio", 1) != 0) {
	//////////////////////////
#ifndef __APPLE__
	//ga_run_single_module_or_quit("audio source", m_asource->threadproc, NULL);
	if(m_asource->start(NULL) < 0)		exit(-1);
#endif
	encoder_register_aencoder(m_aencoder, audio_encoder_param);
	//////////////////////////
	}
	// server
	if(m_server->start(NULL) < 0)		exit(-1);
	//
	return 0;
}

// #ifdef TEST_RECONFIGURE removed for runtime control
static void *
test_reconfig(void *) {
	int s = 0, err;
	int kbitrate[] = { 2000, 8000 };
	int framerate[][2] = { { 12, 1 }, {30, 1}, {24, 1} };
	ga_error("reconfigure thread started ...\n");
	while(1) {
		ga_ioctl_reconfigure_t reconf;
		if(encoder_running() == 0) {
#ifdef WIN32
			Sleep(1);
#else
			sleep(1);
#endif
			continue;
		}
#ifdef WIN32
		Sleep(20 * 1000);
#else
		sleep(20);
#endif
		bzero(&reconf, sizeof(reconf));
		reconf.id = 0;
#if 0
		reconf.bitrateKbps = kbitrate[s%2];
		reconf.bufsize = 5 * kbitrate[s%2] / 24;
#endif
		reconf.framerate_n = framerate[s%3][0];
		reconf.framerate_d = framerate[s%3][1];
		// vsource
		if(m_vsource->ioctl) {
			err = m_vsource->ioctl(GA_IOCTL_RECONFIGURE, sizeof(reconf), &reconf);
			if(err < 0) {
				ga_error("reconfigure vsource failed, err = %d.\n", err);
			} else {
				ga_error("reconfigure vsource OK, framerate=%d/%d.\n",
						reconf.framerate_n, reconf.framerate_d);
			}
		}
		// encoder
		if(m_vencoder->ioctl) {
			err = m_vencoder->ioctl(GA_IOCTL_RECONFIGURE, sizeof(reconf), &reconf);
			if(err < 0) {
				ga_error("reconfigure encoder failed, err = %d.\n", err);
			} else {
				ga_error("reconfigure encoder OK, bitrate=%d; bufsize=%d; framerate=%d/%d.\n",
						reconf.bitrateKbps, reconf.bufsize,
						reconf.framerate_n, reconf.framerate_d);
			}
		}
		s = (s + 1) % 6;
	}
	return NULL;
}
// #endif removed

typedef struct ga_abr_config_s {
	int bitrateKbps;
	int bufsize;
	int framerate_n;
	int framerate_d;
} ga_abr_config_t;

/**
 * @brief 사용자 정의 ABR 알고리즘 함수 (서버 측)
 * @return 1: 설정 변경 필요, 0: 유지
 */
static int
vencoder_abr_algorithm(double udp_rtt, double icmp_rtt, ga_abr_config_t *out_params) {
	// TODO: 여기에 지연 시간에 따른 비트레이트 및 FPS 조절 알고리즘을 구현하세요.
	// 예: if(udp_rtt > 150) { 
	//        out_params->bitrateKbps = 2000;
	//        out_params->framerate_n = 15;
	//     }
	
	// 현재는 동작하지 않는 뼈대만 반환합니다.
	return 0;
}

static void *
abr_controller_thread(void *arg) {
	ga_error("ABR controller thread started ...\n");
	while (1) {
		ga_ioctl_network_status_t net_stat;
		ga_abr_config_t abr_conf;
		ga_ioctl_reconfigure_t reconf;
		int err;

		if (encoder_running() == 0) {
			sleep(1);
			continue;
		}

		// 1. 인코더로부터 최신 네트워크 상태(RTT) 가져오기
		if (m_vencoder->ioctl) {
			err = m_vencoder->ioctl(GA_IOCTL_GET_NETWORK_STATUS, sizeof(net_stat), &net_stat);
			if (err < 0) {
				ga_error("ABR: failed to get network status, err = %d\n", err);
				sleep(1);
				continue;
			}
		}

		// 2. 알고리즘 실행
		bzero(&abr_conf, sizeof(abr_conf));
		if (vencoder_abr_algorithm(net_stat.udp_rtt_ms, net_stat.icmp_rtt_ms, &abr_conf)) {
			// 3. 변경 사항이 있다면 vsource와 vencoder 모두에게 명령 하달
			bzero(&reconf, sizeof(reconf));
			reconf.id = 0;
			reconf.bitrateKbps = abr_conf.bitrateKbps;
			reconf.bufsize = abr_conf.bufsize;
			reconf.framerate_n = abr_conf.framerate_n;
			reconf.framerate_d = abr_conf.framerate_d;

			// vsource (Capture FPS)
			if (reconf.framerate_n > 0 && m_vsource->ioctl) {
				m_vsource->ioctl(GA_IOCTL_RECONFIGURE, sizeof(reconf), &reconf);
			}

			// vencoder (Bitrate & Encoding FPS)
			if (m_vencoder->ioctl) {
				m_vencoder->ioctl(GA_IOCTL_RECONFIGURE, sizeof(reconf), &reconf);
			}
			
			ga_error("ABR: System reconfigured (RTT: UDP=%.2f, ICMP=%.2f) -> Bitrate=%d, FPS=%d/%d\n",
				net_stat.udp_rtt_ms, net_stat.icmp_rtt_ms,
				reconf.bitrateKbps, reconf.framerate_n, reconf.framerate_d);
		}

		usleep(1000000); // 1초 주기로 체크 (조절 가능)
	}
	return NULL;
}

int
main(int argc, char *argv[]) {
	int notRunning = 0;
#ifdef WIN32
	if(CoInitializeEx(NULL, COINIT_MULTITHREADED) < 0) {
		fprintf(stderr, "cannot initialize COM.\n");
		return -1;
	}
#endif
	//
	if(argc < 2) {
		fprintf(stderr, "usage: %s config-file\n", argv[0]);
		return -1;
	}
	//
	if(ga_init(argv[1], NULL) < 0)	{ return -1; }
	//
	ga_openlog();
	//
	if(rtspconf_parse(rtspconf_global()) < 0)
					{ return -1; }
	//
	prect = NULL;
	//
	if(ga_crop_window(&rect, &prect) < 0) {
		return -1;
	} else if(prect == NULL) {
		ga_error("*** Crop disabled.\n");
	} else if(prect != NULL) {
		ga_error("*** Crop enabled: (%d,%d)-(%d,%d)\n", 
			prect->left, prect->top,
			prect->right, prect->bottom);
	}
	//
	if(load_modules() < 0)	 	{ return -1; }
	if(init_modules() < 0)	 	{ return -1; }
	if(run_modules() < 0)	 	{ return -1; }
	//
	if (ga_conf_readbool("enable-reconfigure", 0) != 0) {
		pthread_t t;
		pthread_create(&t, NULL, test_reconfig, NULL);
		ga_error("TEST: Dynamic reconfiguration enabled (via config).\n");
	}
	//
	if (ga_conf_readbool("enable-abr", 0) != 0) {
		pthread_t t;
		pthread_create(&t, NULL, abr_controller_thread, NULL);
		ga_error("ABR: Adaptive Bitrate controller enabled (via config).\n");
	}
	//
	//rtspserver_main(NULL);
	//liveserver_main(NULL);
	while(1) {
		usleep(5000000);
	}
	// alternatively, it is able to create a thread to run rtspserver_main:
	//	pthread_create(&t, NULL, rtspserver_main, NULL);
	//
	ga_deinit();
	//
	return 0;
}

