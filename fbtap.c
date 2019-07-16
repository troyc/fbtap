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

#include <linux/module.h>
#include <linux/device.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
#include <asm/xen/page.h>
#endif

#include "fbtap.h"

#define DEVNAME "fbtap"

struct fbtap_framebuffer {
    unsigned long size;
    void *fb;
    uint64_t pos;
    struct fbdim dim;
    atomic_t counter;
};

static struct {
    struct cdev *cdev;
    int major;
    struct class *class;
} info;

static void
fbtap_vma_open (struct vm_area_struct *vma)
{
    struct fbtap_framebuffer *fb = vma->vm_private_data;
    printk (KERN_DEBUG "fbtap vma open: %d\n",
            atomic_add_return (1, &fb->counter));
}

static void
fbtap_vma_close (struct vm_area_struct *vma)
{
    struct fbtap_framebuffer *fb = vma->vm_private_data;

    printk (KERN_DEBUG "fbtap vma close: %d\n",
            atomic_sub_return (1, &fb->counter));
}

static int
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
fbtap_vma_fault (struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
#else
fbtap_vma_fault (struct vm_area_struct *vma, struct vm_fault *vmf)
{
#endif
    struct page * page;
    unsigned long offset = vmf->pgoff << PAGE_SHIFT;
    int ret = 0;
    struct fbtap_framebuffer *fb = vma->vm_private_data;

    if (offset > fb->size) {
        printk (KERN_ERR "fbtap: offset 0x%lx > size 0x%lx\n", offset, fb->size);
        ret = VM_FAULT_SIGBUS;
        goto nopage_trouble;
    }

    page = vmalloc_to_page (fb->fb + offset);

    if (!page) {
        printk (KERN_ERR "fbtap: could not get page at pgoff 0x%lx\n",
                vmf->pgoff);
        ret = VM_FAULT_SIGBUS;
        goto nopage_trouble;
    }

    get_page(page);
    vmf->page = page;

nopage_trouble:
    return ret;
}

static struct vm_operations_struct fbtap_vm_ops = {
    .open = &fbtap_vma_open,
    .close = &fbtap_vma_close,
    .fault = &fbtap_vma_fault
};

static void
fbinfo_clear (struct fbtap_framebuffer *fb)
{
    fb->fb = NULL;
    fb->size = 0;
    fb->pos = 0;
    fb->dim.xres = 0;
    fb->dim.yres = 0;
    fb->dim.bpp = 0;
    fb->dim.linesize = 0;
    atomic_set (&fb->counter, 0);
}

static int
fbtap_mmap (struct file *filp, struct vm_area_struct *vma)
{
    struct fbtap_framebuffer *fb = filp->private_data;
    unsigned long size;

    if (!(vma->vm_flags & VM_SHARED)) {
        printk (KERN_ERR "fbtap_mmap: non-shared mapping not possible\n");
        return -EINVAL;
    }

    size = PAGE_ALIGN(vma->vm_end - vma->vm_start);

    if (size > fb->size) {
        printk (KERN_ERR "fbtap_mmap: vma to map larger than fb\n");
        return -EINVAL;
    }

    if (vma->vm_pgoff != 0) {
        printk (KERN_ERR "fbtap_mmap: offset != 0\n");
        return -EINVAL;
    }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
    pgprot_val(vma->vm_page_prot) |= cachemode2protval(_PAGE_CACHE_MODE_WC);
#else
    vma->vm_page_prot = __pgprot (((pgprot_val (vma->vm_page_prot)
                | _PAGE_CACHE_WC) & ~_PAGE_PCD));
#endif
    vma->vm_ops = &fbtap_vm_ops;
    vma->vm_private_data = fb;

    // For the first mapping, the vma_open is not called, so we need to do
    // explicitly to increment the counter
    fbtap_vma_open(vma);

    return 0;
}

static long
fbtap_ioctl (struct file *filp, unsigned int cmd, unsigned long arg)
{
    unsigned int p, num_pages;
    unsigned long *pfns;
    unsigned long fbpage;
    struct fbtap_framebuffer *fb = filp->private_data;
    int res = 0;

    switch (cmd) {

    case FBTAP_IOCGDIMS:
        res = copy_to_user ((struct fbdim *) arg, &fb->dim,
                            sizeof (struct fbdim));
        if (res != 0) {
            printk (KERN_ERR "fbtap ioctl: could not copy dim for get_dims\n");
            return -EFAULT;
        }
        break;

    case FBTAP_IOCGMADDRS:
        if (!fb->fb) {
            printk (KERN_ERR "fbtap ioctl: framebuffer is not allocated\n");
            return -EINVAL;
        }

        pfns = (unsigned long *) arg;

        num_pages = fb->size >> PAGE_SHIFT;

        for (p = 0; p < num_pages; p++) {
            fbpage = pfn_to_mfn (vmalloc_to_pfn (fb->fb + p * PAGE_SIZE));

            /* if (p < 6)
                printk (KERN_INFO "fbtap sending page number: %d, virt: %p, pfn: %lx, mfn: %lx\n", p, info.fb + p*PAGE_SIZE, vmalloc_to_pfn (info.fb + p*PAGE_SIZE), fbpage); */

            put_user (fbpage, pfns + p);
        }
        break;

    case FBTAP_IOCGSIZE:
        put_user (fb->size >> PAGE_SHIFT, (unsigned long *)arg);
        break;

    case FBTAP_IOCALLOCFB:
        if (fb->fb && atomic_read (&fb->counter)) {
            printk (KERN_ERR "fbtap: please unmap before reallocate\n");
            return -EFAULT;
        }

        vfree (fb->fb);
        fbinfo_clear (fb);

        res = copy_from_user (&fb->dim, (void *)arg, sizeof (struct fbdim));
        if (res != 0) {
            printk (KERN_ERR "fbtap: could not copy dim args for allocfb\n");
            goto error_clear;
        }

        fb->size = PAGE_ALIGN (fb->dim.linesize * fb->dim.yres);
        printk (KERN_INFO "fbtap: fb is %ux%u, %ubpp, linesize: %uB, size: %luB", 
            fb->dim.xres, fb->dim.yres, fb->dim.bpp, fb->dim.linesize,
            fb->size);

        if (!(fb->fb = vmalloc(fb->size))) {
            printk (KERN_ERR "fbtap ioctl: could not alloc mem for fb\n");
            goto error_clear;
        }

        memset (fb->fb, 0, fb->size);

        // fill fb with nice gradients so we'll know when we see it
        for (p = 0; p < (fb->size); p++)
            ((char *)fb->fb)[p] = p & 0xff;

        break;

    case FBTAP_IOCFREEFB:
        if (!fb->fb) {
            printk (KERN_ERR "fbtap: there was no framebuffer allocated\n");
            return -EFAULT;
        }

        if (atomic_read (&fb->counter)) {
            printk (KERN_ERR "fbtap: please unmap before free\n");
            return -EFAULT;
        }

        vfree (fb->fb);
        fbinfo_clear (fb);
        break;

    default:
        printk (KERN_ERR "fbtap ioctl: unknown cmd: 0x%x\n", cmd);
        return -ENOTTY;
    }

    return 0;

error_clear:
    fbinfo_clear (fb);

    return -EFAULT;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33))
static int
fbtap_ioctl_legacy (struct inode *inode, struct file *filp,
                    unsigned int cmd, unsigned long arg)
{
    return fbtap_ioctl (filp, cmd, arg);
}

#endif  /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)) */

static ssize_t
fbtap_read (struct file *filp, char __user *buf, size_t len, loff_t *offset)
{
    struct fbtap_framebuffer *fb = filp->private_data;
    long res;

    if (!len)
        return 0;

    if (!fb->fb) {
        printk (KERN_ERR "fbtap read: can not read from uninitialised fb - need "
            "to ioctl alloc first\n");

        return -EFAULT;
    }

    if ((fb->pos + len) >= fb->size)
        len = fb->size - fb->pos - 1;

    res = copy_to_user (buf, fb->fb + fb->pos, len);

    if (res > 0)
        fb->pos += res;

    return res;
}

static ssize_t
fbtap_write (struct file *filp, const char __user *buf, size_t len, loff_t *offset)
{
    struct fbtap_framebuffer *fb = filp->private_data;
    long res;

    if (!len)
        return 0;

    if (!fb->fb) {
        printk (KERN_ERR "fbtap write: can not write to uninitialised fb - need "
            "to ioctl alloc first\n");

        return -EFAULT;
    }

    if ((fb->pos + len) >= fb->size)
        len = fb->size - fb->pos - 1;

    res = copy_from_user (fb->fb + fb->pos, buf, len);


    if (res > 0)
        fb->pos += res;

    return res;
}



loff_t
fbtap_llseek (struct file *filp, loff_t offset, int whence)
{
    struct fbtap_framebuffer *fb = filp->private_data;
    int ret = 0;

    switch (whence) {
    case SEEK_SET:
        if (offset < fb->size) {
            fb->pos = offset;
        } else {
            ret = -EOVERFLOW;
        }
        break;
    case SEEK_CUR:
        fb->pos = offset & fb->size;
        break;
    case SEEK_END:
    default:
        ret = -EINVAL;
    }

    return ret;
}

static int
fbtap_open (struct inode *inode, struct file *filp)
{
    struct fbtap_framebuffer *fb;

    fb = vmalloc(sizeof (*fb));

    if (!fb) {
        printk (KERN_ERR "fbtap open(): can't allocate private data\n");
        return -1;
    }

    fbinfo_clear (fb);

    filp->private_data = fb;

    return 0;
}

static int
fbtap_close (struct inode *inode, struct file *filp)
{
    // we don't free the fb here, that's the whole point of the thing...
    return 0;
}

static struct file_operations fbtap_fops = {
    .owner = THIS_MODULE,
    .read = &fbtap_read,
    .write = &fbtap_write,
    .open = &fbtap_open,
    .release = &fbtap_close,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36))
    .unlocked_ioctl = &fbtap_ioctl,
#else
    .ioctl = &fbtap_ioctl_legacy,
#endif
    .llseek = &fbtap_llseek,
    .mmap = &fbtap_mmap
};

static int __init
fbtap_init (void)
{
    if (0 > (info.major = register_chrdev (0, DEVNAME, &fbtap_fops))) {
        printk (KERN_ERR "fbtap register_chrdev failed\n");
        return -1;
    }

    if (IS_ERR (info.class = class_create (THIS_MODULE, DEVNAME))) {
        printk (KERN_ERR "fbtap class_create failed\n");
        goto fail_1;
    }

    if (IS_ERR (device_create (info.class, NULL, MKDEV (info.major, 0), NULL, DEVNAME))) {
        printk (KERN_ERR "fbtap device_create failed\n");
        goto fail_2;
    }

    return 0;

fail_2:
    class_destroy (info.class);

fail_1:
    unregister_chrdev (info.major, DEVNAME);
    return -1;
}

static void __exit
fbtap_remove (void)
{
    device_destroy (info.class, MKDEV (info.major, 0));
    class_destroy (info.class);
    unregister_chrdev (info.major, DEVNAME);
}

module_init(fbtap_init);
module_exit(fbtap_remove);

MODULE_LICENSE("GPL");

