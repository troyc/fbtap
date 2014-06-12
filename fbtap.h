/*
 * Copyright (c) 2012 Citrix Systems, Inc.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef FBTAPH_
#define FBTAPH_
#include <linux/ioctl.h>


struct fbdim {
	unsigned int xres;
	unsigned int yres;
	unsigned int bpp;      // bits per pixel
	unsigned int linesize;   // linesize in bytes
};


#define FBTAP_IOCTL_MAGIC '^' // this is the hat from the xen logo..

// ptr to uint: number of pages
#define FBTAP_IOCGSIZE _IOR (FBTAP_IOCTL_MAGIC, 1, unsigned long)

// array of unsigned long ints: machine addresses
#define FBTAP_IOCGMADDRS _IOR (FBTAP_IOCTL_MAGIC, 2, unsigned long)

// allocate a new fb with dimensions
#define FBTAP_IOCALLOCFB _IOW (FBTAP_IOCTL_MAGIC, 3, struct fbdim)

// get dimensions
#define FBTAP_IOCGDIMS _IOR (FBTAP_IOCTL_MAGIC, 4, struct fbdim)

// free currently allocated fb
#define FBTAP_IOCFREEFB _IO (FBTAP_IOCTL_MAGIC, 5)


#endif
