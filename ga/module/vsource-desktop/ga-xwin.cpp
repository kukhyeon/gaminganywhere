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
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "ga-common.h"
#include "ga-xwin.h"

static int screenNumber;
static int width, height, depth;

static char *displayname = NULL;
static Display *display = NULL;
static Window rootWindow;
static Screen *screen = NULL;
static XImage *image = NULL;

static XShmSegmentInfo __xshminfo;
static bool __xshmattached = false;
static bool __xshmfailed = false;

static int __x11err_code = 0;
static int __x11err_request = 0;
static int __x11err_minor = 0;
static int (*__x11err_prevhandler)(Display*, XErrorEvent*) = NULL;

static int
ga_xwin_xerror_handler(Display *dpy, XErrorEvent *ev) {
	(void) dpy;
	__x11err_code = ev->error_code;
	__x11err_request = ev->request_code;
	__x11err_minor = ev->minor_code;
	return 0;
}

static void
ga_xwin_begin_xerror_trap() {
	__x11err_code = 0;
	__x11err_request = 0;
	__x11err_minor = 0;
	__x11err_prevhandler = XSetErrorHandler(ga_xwin_xerror_handler);
	XSync(display, False);
}

static int
ga_xwin_end_xerror_trap(const char *op) {
	char emsg[128];
	XSync(display, False);
	XSetErrorHandler(__x11err_prevhandler);
	if(__x11err_code == 0)
		return 0;
	XGetErrorText(display, __x11err_code, emsg, sizeof(emsg));
	ga_error("ga_xwin_capture: %s X11 error=%d(%s) request=%d minor=%d\n",
		op, __x11err_code, emsg, __x11err_request, __x11err_minor);
	return -1;
}

int
ga_xwin_init(const char *displayname, gaImage *gaimg) {
	int ignore = 0;
	//
	bzero(&__xshminfo, sizeof(__xshminfo));
	__xshmfailed = false;
	// open display
	if((display = XOpenDisplay(displayname)) == NULL) {
		ga_error("cannot open display \"%s\"\n", displayname ? displayname : "DEFAULT");
		return -1;
	}
	ga_error("ga_xwin_init: DISPLAY=%s, XDG_SESSION_TYPE=%s, WAYLAND_DISPLAY=%s\n",
		getenv("DISPLAY") ? getenv("DISPLAY") : "(null)",
		getenv("XDG_SESSION_TYPE") ? getenv("XDG_SESSION_TYPE") : "(null)",
		getenv("WAYLAND_DISPLAY") ? getenv("WAYLAND_DISPLAY") : "(null)");
	// check MIT extension
	if(XQueryExtension(display, "MIT-SHM", &ignore, &ignore, &ignore) ) {
		int major, minor;
		Bool pixmaps;
		if(XShmQueryVersion(display, &major, &minor, &pixmaps) == True) {
			ga_error("XShm extention version %d.%d %s shared pixmaps\n",
					major, minor, (pixmaps==True) ? "with" : "without");
		} else {
			ga_error("XShm extension not supported.\n");
			goto xcap_init_error;
		}
	}
	// get default screen
	screenNumber = XDefaultScreen(display);
	if((screen = XScreenOfDisplay(display, screenNumber)) == NULL) {
		ga_error("cannot obtain screen #%d\n", screenNumber);
		goto xcap_init_error;
	}
	//
	width = XDisplayWidth(display, screenNumber);
	height = XDisplayHeight(display, screenNumber);
	depth = XDisplayPlanes(display, screenNumber);
	ga_error("X-Window-init: dimension: %dx%dx%d @ %d/%d\n",
			width, height, depth,
			screenNumber, XScreenCount(display));
	//
	if((image = XShmCreateImage(display,
			XDefaultVisual(display, screenNumber),
			depth, ZPixmap, NULL, &__xshminfo,
			width, height)) == NULL) {
		ga_error("XShmCreateImage failed.\n");
		goto xcap_init_error;
	}
	//
	if((__xshminfo.shmid = shmget(IPC_PRIVATE,
				image->bytes_per_line*image->height,
				IPC_CREAT | 0777)) < 0) {
		perror("shmget");
		goto xcap_init_error;
	}
	//
	__xshminfo.shmaddr = image->data = (char*) shmat(__xshminfo.shmid, 0, 0);
	__xshminfo.readOnly = False;
	if(XShmAttach(display, &__xshminfo) == 0) {
		ga_error("XShmAttach failed.\n");
		goto xcap_init_error;
	}
	//
	__xshmattached = true;
	rootWindow = XRootWindow(display, screenNumber);
	gaimg->width = image->width;
	gaimg->height = image->height;
	gaimg->bytes_per_line = image->bytes_per_line;
	//
	return 0;
	//
xcap_init_error:
	ga_xwin_deinit();
	return -1;
}

void
//ga_xwin_deinit(Display *display, XImage *image) {
ga_xwin_deinit() {
	//
	if(__xshmattached) {
		XShmDetach(display, &__xshminfo);
		__xshmattached = false;
	}
	//
	if(__xshminfo.shmaddr) {
		shmctl(__xshminfo.shmid, IPC_RMID, NULL);
		__xshminfo.shmaddr = NULL;
	}
	if(image)	XDestroyImage(image);
	if(display)	XCloseDisplay(display);
	//
	image = NULL;
	display = NULL;
	//
	return;
}

void
ga_xwin_imageinfo(XImage *image) {
	ga_error("ga-imageinfo: %dx%dx%d xoffset=%d format=%d byte-order=%d\n",
			image->width, image->height, image->depth,
			image->xoffset, image->format, image->byte_order);
	ga_error("ga-imageinfo: --> bitmap-unit=%d bitmap-bit-order=%d bitmap-pad=%d\n",
			image->bitmap_unit, image->bitmap_bit_order, image->bitmap_pad);
	ga_error("ga-imageinfo: --> bytes-per-line=%d bits-per-pixel=%d\n",
			image->bytes_per_line, image->bits_per_pixel);
	ga_error("ga-imageinfo: --> mask red=0x%08lx green=0x%08lx blue=0x%08lx\n",
			image->red_mask, image->green_mask, image->blue_mask);
	return;
}

void
ga_xwin_capture(char *buf, int buflen, struct gaRect *rect) {
	int requiredSize;
	XImage *captured = image;
	bool use_xgetimage = __xshmfailed;
	if(rect == NULL) {
		requiredSize = image->height * image->bytes_per_line;
	} else {
		requiredSize = rect->height * rect->linesize;
	}
	if(buflen < requiredSize) {
		ga_error("ga_xwin_capture: buffer too small (%d < %d), frame dropped.\n", buflen, requiredSize);
		return;
	}
	if(use_xgetimage == false) {
		ga_xwin_begin_xerror_trap();
		if(XShmGetImage(display, rootWindow, image, 0, 0, XAllPlanes()) != 0
		&& ga_xwin_end_xerror_trap("XShmGetImage") == 0) {
			captured = image;
		} else {
			if(__xshmfailed == false) {
				ga_error("ga_xwin_capture: XShmGetImage failed, switching to XGetImage fallback.\n");
				__xshmfailed = true;
			}
			ga_xwin_begin_xerror_trap();
			captured = XGetImage(display, rootWindow, 0, 0,
					image->width, image->height, XAllPlanes(), ZPixmap);
			if(ga_xwin_end_xerror_trap("XGetImage") != 0)
				captured = NULL;
			if(captured == NULL) {
				ga_error("ga_xwin_capture: XGetImage fallback failed, frame dropped.\n");
				bzero(buf, requiredSize);
				return;
			}
		}
	} else {
		ga_xwin_begin_xerror_trap();
		captured = XGetImage(display, rootWindow, 0, 0,
				image->width, image->height, XAllPlanes(), ZPixmap);
		if(ga_xwin_end_xerror_trap("XGetImage") != 0)
			captured = NULL;
		if(captured == NULL) {
			ga_error("ga_xwin_capture: XGetImage fallback failed, frame dropped.\n");
			bzero(buf, requiredSize);
			return;
		}
	}
	if(rect == NULL) {
		int sourceSize = captured->height * captured->bytes_per_line;
		if(sourceSize < requiredSize) {
			ga_error("ga_xwin_capture: source image too small (%d < %d), frame dropped.\n", sourceSize, requiredSize);
			bzero(buf, requiredSize);
			if(captured != image)
				XDestroyImage(captured);
			return;
		}
		bcopy(captured->data, buf, requiredSize/*buflen*/);
	} else {
		int i;
		char *src, *dst;
		src = ((char *) image->data);
		if(rect->top < 0 || rect->left < 0
		|| rect->top + rect->height > captured->height
		|| rect->left + rect->width > captured->width) {
			ga_error("ga_xwin_capture: invalid crop rect, frame dropped.\n");
			bzero(buf, requiredSize);
			if(captured != image)
				XDestroyImage(captured);
			return;
		}
		src = ((char *) captured->data);
		src += captured->bytes_per_line * rect->top;
		dst = (char*) buf;
		//
		for(i = 0; i < rect->height; i++) {
			bcopy(src, dst, rect->linesize);
			src += captured->bytes_per_line;
			dst += rect->linesize;
		}
	}
		if(captured != image)
		XDestroyImage(captured);
	return;
}
