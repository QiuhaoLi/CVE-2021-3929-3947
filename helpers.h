#ifndef HEADER_HELPERS
#define HEADER_HELPERS

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>

volatile void *dev_mmio_map(volatile void *mmio_region_guest_phys_address, size_t len)
{
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd == -1)
    {
        perror("open /dev/mem");
        exit(EXIT_FAILURE);
    }

    void *mmio_region_guest_virt_address = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)mmio_region_guest_phys_address);
    if (!mmio_region_guest_virt_address)
    {
        perror("mmap /dev/mem");
        exit(EXIT_FAILURE);
    }

    close(fd);
    return mmio_region_guest_virt_address;
}

void *virt_to_phys(const void *addr)
{
#define PAGEMAP_LENGTH sizeof(size_t)
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1)
    {
        perror("open /proc/self/pagemap");
        exit(EXIT_FAILURE);
    }

    size_t offset = (size_t)addr / getpagesize() * PAGEMAP_LENGTH;
    lseek(fd, offset, SEEK_SET);

    size_t page_frame_number = 0;
    if (read(fd, &page_frame_number, PAGEMAP_LENGTH) != PAGEMAP_LENGTH)
    {
        perror("open /proc/self/pagemap: read page_frame_number");
        exit(EXIT_FAILURE);
    }

    page_frame_number &= 0x7FFFFFFFFFFFFF;

    close(fd);

    return (void *)((page_frame_number << 12) | ((size_t)addr & 0xfff));
}

void *get_continuous_phys_pages(unsigned int num_pages)
{
    void *buf = NULL;
    void *mem = NULL;
    int page_size = getpagesize();
    do
    {
        const size_t map_len = page_size * page_size;
        if (mem != NULL)
        {
            munmap(mem, map_len);
        }
        mem = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        mlock(mem, map_len);
        memset(mem, 0, map_len);
        for (void *vp1 = mem; vp1 < mem + map_len; vp1 += page_size)
        {
            bool flag = true;
            /* num pages need to be physical continous. Wish us good luck, HACKISH! */
            for (size_t i = 0; i < num_pages - 1; i++)
            {
                void *vp_tmp1 = vp1 + i * page_size;
                void *vp_tmp2 = vp_tmp1 + page_size;
                if (vp_tmp1 < mem + map_len && vp_tmp2 < mem + map_len && virt_to_phys(vp_tmp1) + page_size == virt_to_phys(vp_tmp2))
                {
                    continue;
                }
                else
                {
                    flag = false;
                    break;
                }
            }
            if (flag)
            {
                buf = vp1;
                break;
            }
        }
    } while (buf == NULL);
    return buf;
}


#endif