/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <linux/fb.h>
#include <linux/kd.h>
#include <cutils/klog.h>
#include <string.h>
#include "font8x8.h"

static unsigned int lx=0, ly=0;
static int fb_fd=-1;

struct FB {
    unsigned char *bits;
    unsigned size;
    struct fb_fix_screeninfo fi;
    struct fb_var_screeninfo vi;
};

static void full_close() {
    close(fb_fd);
    fb_fd = -1;
}

static int fb_open(struct FB *fb)
{
	if (fb_fd < 0) {
	    fb_fd = open("/dev/graphics/fb0", O_RDWR);
	    if (fb_fd < 0) {
		klog_write(0, "no graphics\n");
		return -1;
	    }
	}

    if (ioctl(fb_fd, FBIOGET_FSCREENINFO, &fb->fi) < 0) {
		klog_write(0, "no FBIOGET_FSCREENINFO\n");
		goto fail;
	}
    if (ioctl(fb_fd, FBIOGET_VSCREENINFO, &fb->vi) < 0) {
		klog_write(0, "no FBIOGET_FSCREENINFO\n");
        goto fail;
    }

    fb->bits = (unsigned char *)mmap(0, fb->fi.line_length * fb->vi.yres, PROT_READ | PROT_WRITE,
                    MAP_SHARED, fb_fd, 0);
    if (fb->bits == MAP_FAILED) {
	klog_write(0, "no MMAP\n");
        goto fail;
    }

    return 0;

fail:
    full_close();
    return -1;
}

static void fb_close(struct FB *fb)
{
    munmap(fb->bits, fb->fi.line_length * fb->vi.yres);
    // only for case when exist troubles
    // with open already opened file in different thread
    // full_close();
}

/* there's got to be a more portable way to do this ... */
static void fb_update(struct FB *fb)
{
    fb->vi.yoffset = 1;
    ioctl(fb_fd, FBIOPUT_VSCREENINFO, &fb->vi);
    fb->vi.yoffset = 0;
    ioctl(fb_fd, FBIOPUT_VSCREENINFO, &fb->vi);
}

void vt_create_nodes()
{
    int fd;
    fd = open("/dev/tty0", O_RDWR | O_SYNC);
    if (fd < 0) {
		mknod("/dev/tty0", 8624, makedev(4, 0));
	} else {
		close(fd);
	}
	fd = open("/dev/graphics/fb0", O_RDWR);
    if (fd < 0) {
        mkdir("/dev/graphics/", 0755);
        mknod("/dev/graphics/fb0", 8624, makedev(29, 0));
	} else {
		close(fd);
	}
}

static int vt_set_mode(int graphics)
{
    int fd, r;
    fd = open("/dev/tty0", O_RDWR | O_SYNC);
    if (fd < 0) {
        return -1;
    }
    r = ioctl(fd, KDSETMODE, graphics ? KD_GRAPHICS : KD_TEXT);
    close(fd);
    return r;
}

void set_pixel(struct FB *fb, short r, short g, short b, short x, short y) {
	long long pixel_color = 0;
	long red = (r & 0xFFFF) >> (16 - fb->vi.red.length);
	long green = (g & 0xFFFF) >> (16 - fb->vi.green.length);
	long blue = (b & 0xFFFF) >> (16 - fb->vi.blue.length);
	long count_bytes = fb->vi.bits_per_pixel / 8;
	unsigned char * write_pos = fb->bits + x * count_bytes + y * fb->fi.line_length;
	pixel_color =
		(red << fb->vi.red.offset) |
		(green << fb->vi.green.offset) |
		(blue << fb->vi.blue.offset);
	memcpy(write_pos, &pixel_color, count_bytes);
}

int write_text(const char *fn)
{
    struct FB fb;
    unsigned int i, x, y;
    unsigned short value, mask;

    klog_write(0, ">%s", fn);

    vt_set_mode(1);

    if (fb_open(&fb)) {
	klog_write(0, "troubles with framebuffer\n");
        goto fail_unmap_data;
    }

    for(i = 0; i < strlen(fn); i ++) {
	if (fn[i] == '\n') {
	    for(x=lx; x < (fb.vi.xres); x ++) {
		for(y=0; y < 8; y ++) {
		    set_pixel(&fb, 0, 0, 0, x, ly + y);
		}
	    }
	    ly += 8;
	    lx = 0;
	    if (ly < (fb.vi.yres - 8)) {
		for(x=0; x < fb.vi.xres; x ++) {
		    for(y=0; y < 8; y ++) {
			set_pixel(&fb, 0, 0xffff, 0xffff, x, ly + y);
		    }
		}
	    }
	    continue;
	}
	if (lx >= fb.vi.xres) {
		lx = 0;
		ly += 8;
	}
	if (ly >= (fb.vi.yres - 8)) {
		ly = 0;
		/*
		 * you can add some sleep for check
		 * what already done on this page
		 * sleep(1);
		 */
	}
	for (x = 0; x < 8; x++) {
	    for (y = 0; y < 8; y++) {
		mask = font8x8[fn[i] * 8 + y];
		/* font pixels: 0 - right, 7 - left */
		value = (mask & (1 << (7 - x))) == 0 ? 0 : 0xffff;
		set_pixel(&fb, value, value, value, lx + x, ly + y);
	    }
	}
	lx += 8;
    }
    fb_update(&fb);
    fb_close(&fb);
    return 0;

fail_unmap_data:
    vt_set_mode(0);
    return -1;
}
