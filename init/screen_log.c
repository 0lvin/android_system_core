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

#include "font8x8_basic.h"

static unsigned int lx=0, ly=0;

struct FB {
    unsigned short *bits;
    unsigned size;
    int fd;
    struct fb_fix_screeninfo fi;
    struct fb_var_screeninfo vi;
};

#define fb_width(fb) ((fb)->vi.xres)
#define fb_height(fb) ((fb)->vi.yres)
#define fb_size(fb) ((fb)->vi.xres * (fb)->vi.yres * 2)

static int fb_open(struct FB *fb)
{
    fb->fd = open("/dev/graphics/fb0", O_RDWR);
    if (fb->fd < 0) {
		klog_write(0, "no graphics\n");
        return -1;
    }

    if (ioctl(fb->fd, FBIOGET_FSCREENINFO, &fb->fi) < 0) {
		klog_write(0, "no FBIOGET_FSCREENINFO\n");
		goto fail;
	}
    if (ioctl(fb->fd, FBIOGET_VSCREENINFO, &fb->vi) < 0) {
		klog_write(0, "no FBIOGET_FSCREENINFO\n");
        goto fail;
    }

    fb->bits = mmap(0, fb_size(fb), PROT_READ | PROT_WRITE,
                    MAP_SHARED, fb->fd, 0);
    if (fb->bits == MAP_FAILED) {
		klog_write(0, "no MMAP\n");
        goto fail;
    }

    return 0;

fail:
    close(fb->fd);
    return -1;
}

static void fb_close(struct FB *fb)
{
    munmap(fb->bits, fb_size(fb));
    close(fb->fd);
}

/* there's got to be a more portable way to do this ... */
static void fb_update(struct FB *fb)
{
    fb->vi.yoffset = 1;
    ioctl(fb->fd, FBIOPUT_VSCREENINFO, &fb->vi);
    fb->vi.yoffset = 0;
    ioctl(fb->fd, FBIOPUT_VSCREENINFO, &fb->vi);
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
		klog_write(0, "no tty\n");
        return -1;
    }
    r = ioctl(fd, KDSETMODE, (void*) (graphics ? KD_GRAPHICS : KD_TEXT));
    close(fd);
    return r;
}

int write_text(const char *fn)
{
    struct FB fb;
    unsigned short *data, *bits, *ptr;
    unsigned count, max;
    int fd;
    unsigned int i, x, y;
    unsigned short value, mask;

	klog_write(0, "screen: %s", fn);

    if (vt_set_mode(1)) {
		klog_write(0, "no mode\n");
    }

    if (fb_open(&fb))
        goto fail_unmap_data;

    bits = fb.bits;
    for(i = 0; i < strlen(fn); i ++) {
		if (fn[i] > 0) {
			if (fn[i] == '\n') {
				ly += fb_width(&fb) * 8;
				lx = 0;
				continue;
			}
			if (lx >= (fb_width(&fb) - 8)) {
				lx = 0;
				ly += fb_width(&fb) * 8;
			}
			if (ly >= (fb_width(&fb) * fb_height(&fb))) {
				ly = 0;
			}
			for (x = 0; x < 8; x++) {
				for (y = 0; y < 8; y++) {
					mask = font8x8_basic[fn[i]][y];
					value = (mask & (1 << x)) == 0 ? 0 : 0xffff;
					bits[lx + ly + x + y * fb_width(&fb)] = value;
				}
			}
			lx += 8;
		}
	}
    fb_update(&fb);
    fb_close(&fb);
    return 0;

fail_unmap_data:
    vt_set_mode(0);
    return -1;
}

