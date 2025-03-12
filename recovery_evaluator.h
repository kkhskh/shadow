#ifndef _RECOVERY_EVALUATOR_H
#define _RECOVERY_EVALUATOR_H

#include <linux/types.h>

/* Recovery phases */
enum recovery_phase {
    PHASE_NONE = 0,
    PHASE_FAILURE_DETECTED,
    PHASE_DRIVER_STOPPED,
    PHASE_DRIVER_RESTARTING,
    PHASE_RECOVERY_COMPLETE,
    PHASE_RECOVERY_FAILED
};

/* Structure to track a recovery test case */
struct recovery_test {
    char name[64];
    char driver[64];
    unsigned long start_time;
    unsigned long end_time;
    bool completed;
    bool success;
};

/* Function declarations */
extern int start_test(const char *name, const char *driver);
extern int end_test(bool success);
extern int add_event(struct recovery_test *test, enum recovery_phase phase, 
                    const char *fmt, ...);

#endif /* _RECOVERY_EVALUATOR_H */