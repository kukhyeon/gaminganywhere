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

static int g_current_bitrate = 0;
static int g_current_fps = 0;
static FILE *savefp_abr = NULL;
static int abr_log_seq = 0;

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

int
calculate_new_bitrate(long long diff, int current_bitrate){
	int new_bitrate;
	// 지연 차이가 크면 급격히 감소, 작으면 완만하게 증가
	if (diff > 100) { // 50ms 초과
		new_bitrate = (int)(current_bitrate * 0.85); // 15% 감소 
	} else {
		// 네트워크 지연(diff)이 적을수록(좋을수록) 더 과감하게 비트레이트를 올립니다.
		// diff = 0ms 일 때 +1000 Kbps (최대 증가폭)
		// diff = 50ms 일 때 +0 Kbps (증가 없음)
		// 공식: 1000 - (diff * 20)
		int increase_amount = 1000 - (int)(diff * 10.0); 
		
		// 음수 방지 및 최대치 제한 (0 ~ 1000Kbps)
		if (increase_amount < 0) increase_amount = 0;
		if (increase_amount > 1000) increase_amount = 1000;
		
		new_bitrate = current_bitrate + increase_amount;
	}

	if (new_bitrate < 500) return 500;
	if (new_bitrate > 8000) return 8000;
	return new_bitrate;
}

int
calculate_new_fps(long long diff, int current_fps){
	// 일단 보류
	/*
    if (diff > 50) {
        int next_fps = current_fps - 3;
        return (next_fps < 15) ? 15 : next_fps; // 최소 15fps
    } else {
        int next_fps = current_fps + 1;
        return (next_fps > 60) ? 60 : next_fps; // 최대 60fps로 제한 (120 점프 방지)
    }
	*/
	int next_fps = 60;
	return next_fps;
}

static int
vencoder_abr_algorithm(double udp_rtt, double icmp_rtt, ga_abr_config_t *out_params) {
    // RTT 차이 계산 (ms 단위 가정)
    long long diff = (long long)(udp_rtt - icmp_rtt);
    
    // 이전 값을 바탕으로 새 값 계산 및 전역 변수 업데이트
    g_current_bitrate = calculate_new_bitrate(diff, g_current_bitrate);
    g_current_fps = calculate_new_fps(diff, g_current_fps);

    // 출력 파라미터 설정
    out_params->bitrateKbps = g_current_bitrate;
    out_params->framerate_n = g_current_fps;
    out_params->framerate_d = 1;
    
    // 버퍼 사이즈 설정: 비트레이트의 절반(0.5초 분량)으로 설정하여 안정성 확보
    out_params->bufsize = g_current_bitrate / 2; 

	// --- CSV 파일에 기록 ---
	if (savefp_abr != NULL) {
		struct timeval now;
		gettimeofday(&now, NULL);
		ga_save_printf(savefp_abr, "%d,%u.%06u,%d,%d,%lld\n", 
					abr_log_seq++, now.tv_sec, now.tv_usec, 
					g_current_bitrate, g_current_fps, diff);
	}

	ga_error("ABR: Update - Seq:%d, Bitrate:%dKbps, FPS:%d\n", 
			abr_log_seq-1, g_current_bitrate, g_current_fps);

    ga_error("ABR: Update - Diff:%lldms, Bitrate:%dKbps, FPS:%d, Buf:%d\n", 
             diff, g_current_bitrate, g_current_fps, out_params->bufsize);

    return 1; // 설정이 변경되었음을 알림
}

static void *
abr_controller_thread(void *arg) {
	ga_error("ABR controller thread started ...\n");

	if (savefp_abr == NULL) {
		char savefile_abr[128] = "abr_log.csv"; // 기본 파일명
		// 설정 파일에서 경로를 읽어오고 싶다면 ga_conf_readv 활용 가능
		savefp_abr = ga_save_init_txt(savefile_abr);
		if (savefp_abr) {
			ga_save_printf(savefp_abr, "Seq,Timestamp,Bitrate(Kbps),FPS,Diff(ms)\n");
			ga_error("SERVER: ABR log file initialized: %s\n", savefile_abr);
		}
	}

	// --- 초기값 읽기 로직 추가 ---
	if (g_current_fps == 0) {
		// video-x264.conf 의 video-fps 값 읽기 (기본값 30)
		g_current_fps = ga_conf_readint("video-fps");
		if (g_current_fps == 0) g_current_fps = 30;
	}
	if (g_current_bitrate == 0) {
		// video-x264-param.conf 의 video-specific[b] 값 읽기
		// 설정 파일에는 bps 단위(예: 3000000)로 되어 있으므로 Kbps로 변환 (/1000)
		g_current_bitrate = ga_conf_mapreadint("video-specific", "b") / 1000;
		if (g_current_bitrate == 0) g_current_bitrate = 3000;
	}
	ga_error("ABR: Initialized with Bitrate:%dKbps, FPS:%d\n", g_current_bitrate, g_current_fps);
	// --------------------------
	
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

