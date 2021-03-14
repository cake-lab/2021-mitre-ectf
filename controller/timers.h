/*
 * Author: Jake Grycel - jtgrycel@wpi.edu
 * Description: Timer configuration module for DTLS and SCUM timing requirements
 */

#ifndef TIMERS_H
#define TIMERS_H

#include "lm3s/lm3s_cmsis.h"
#include <stdint.h>

/*
 * Globals
 */

extern unsigned char fin_timer_event;
extern unsigned char sync_timer_event;

/*
 * Definitions
 */

// Hardware times
#define INT_TIMER TIMER0
#define FIN_TIMER TIMER1
#define SYNC_TIMER TIMER2

// Timer configuration constants
#define TICKS_PER_MS 12583
#define MAX_MS_VAL   (0xFFFFFFFF/TICKS_PER_MS)

// Timer register configurtaion constants
#define TAEN_BIT      ((uint32_t)(1 << 0))
#define CFG_MASK      ((uint32_t)(0x00000007))
#define MODE_MASK     ((uint32_t)(0x00000003))
#define MODE_ONESHOT  ((uint32_t)(1 << 0))
#define TA_INT_BIT    ((uint32_t)(1 << 0))


/*
 * Function Prototypes
 */

void timers_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms);
int timers_get_delay(void *data);
void timers_set_sync_timeout(uint32_t ms);

#endif // TIMERS_H