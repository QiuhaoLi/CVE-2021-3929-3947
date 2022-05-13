#ifndef HEADER_QEMU
#define HEADER_QEMU

#include <stdint.h>
#include <pthread.h>

#define NVME_OFFSET_ACQ (0x30)
#define NVME_OFFSET_ASQ (0x28)
#define NVME_OFFSET_AQA (0x24)
#define NVME_OFFSET_CC (0x14)
#define NVME_OFFSET_SQyTDBL (0x1000)

#define HDA_OFFSET_IN0_LVI (0x8c)
#define HDA_OFFSET_IN1_LVI (0xac)
#define HDA_OFFSET_IN2_LVI (0xcc)
#define HDA_OFFSET_IN3_LVI (0xec)
#define HDA_OFFSET_ICH6_REG_GCTL (0x8)
#define HDA_OFFSET_IN0_CTL (0x80)
#define HDA_OFFSET_IN1_CTL (0xa0)
#define HDA_OFFSET_IN2_CTL (0xc0)
#define HDA_OFFSET_IN3_CTL (0xe0)
#define HDA_OFFSET_IN0_BDLPL (0x98)
#define HDA_OFFSET_IN0_BDLPU (0x9c)

#define QEMU_PACKED __attribute__((packed))

typedef struct QEMU_PACKED NvmeSglDescriptor
{
    uint64_t addr;
    uint32_t len;
    uint8_t rsvd[3];
    uint8_t type;
} NvmeSglDescriptor;

typedef union NvmeCmdDptr
{
    struct
    {
        uint64_t prp1;
        uint64_t prp2;
    };

    NvmeSglDescriptor sgl;
} NvmeCmdDptr;

enum NvmePsdt
{
    NVME_PSDT_PRP = 0x0,
    NVME_PSDT_SGL_MPTR_CONTIGUOUS = 0x1,
    NVME_PSDT_SGL_MPTR_SGL = 0x2,
};

typedef struct QEMU_PACKED NvmeCmd
{
    uint8_t opcode;
    uint8_t flags;
    uint16_t cid;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    NvmeCmdDptr dptr;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NvmeCmd;

typedef struct QEMU_PACKED NvmeCqe
{
    uint32_t result;
    uint32_t dw1;
    uint16_t sq_head;
    uint16_t sq_id;
    uint16_t cid;
    uint16_t status;
} NvmeCqe;

typedef enum
{
    QEMU_CLOCK_REALTIME = 0,
    QEMU_CLOCK_VIRTUAL = 1,
    QEMU_CLOCK_HOST = 2,
    QEMU_CLOCK_VIRTUAL_RT = 3,
    QEMU_CLOCK_MAX
} QEMUClockType;

#define QLIST_ENTRY(type)                                             \
    struct                                                            \
    {                                                                 \
        struct type *le_next;  /* next element */                     \
        struct type **le_prev; /* address of previous next element */ \
    }

#define QLIST_HEAD(name, type)                     \
    struct name                                    \
    {                                              \
        struct type *lh_first; /* first element */ \
    }

typedef struct QemuMutex QemuMutex;
struct QemuMutex
{
    pthread_mutex_t lock;
#ifdef CONFIG_DEBUG_MUTEX
    const char *file;
    int line;
#endif
    bool initialized;
};

typedef struct QEMUClock
{
    /* We rely on BQL to protect the timerlists */
    QLIST_HEAD(, QEMUTimerList)
    timerlists;

    QEMUClockType type;
    bool enabled;
} QEMUClock;

typedef struct QemuEvent QemuEvent;
struct QemuEvent
{
    unsigned value;
    bool initialized;
};

/* A QEMUTimerList is a list of timers attached to a clock. More
 * than one QEMUTimerList can be attached to each clock, for instance
 * used by different AioContexts / threads. Each clock also has
 * a list of the QEMUTimerLists associated with it, in order that
 * reenabling the clock can call all the notifiers.
 */
typedef void QEMUTimerListNotifyCB(void *opaque, QEMUClockType type);
typedef struct QEMUTimerList QEMUTimerList;
typedef struct QEMUTimer QEMUTimer;
struct QEMUTimerList
{
    QEMUClock *clock;
    QemuMutex active_timers_lock;
    QEMUTimer *active_timers;
    QLIST_ENTRY(QEMUTimerList)
    list;
    QEMUTimerListNotifyCB *notify_cb;
    void *notify_opaque;

    /* lightweight method to mark the end of timerlist's running */
    QemuEvent timers_done_ev;
};

typedef void QEMUTimerCB(void *opaque);
struct QEMUTimer
{
    int64_t expire_time; /* in nanoseconds */
    QEMUTimerList *timer_list;
    QEMUTimerCB *cb;
    void *opaque;
    QEMUTimer *next;
    int attributes;
    int scale;
};

#endif