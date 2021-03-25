/*
 * Author: Jake Grycel - jtgrycel@wpi.edu
 * Description: Timer configuration module for DTLS and SCUM timing requirements
 */

#include "dtls.h"
#include "timers.h"

/*
 * Global ISR info
 */

unsigned char fin_timer_event = 0;
unsigned char sync_timer_event = 0;
static struct dtls_timers *sw_timer_ref;


/*
 * Internal Functions
 */

// Configure timer
static void config_hw_timer(TIMER_Type *hw_timer, uint32_t load_val)
{
  hw_timer->CTL   &= ~TAEN_BIT;      // Disable
  hw_timer->CFG   &= ~CFG_MASK;      // Use 32-bit timer
  hw_timer->TAMR  &= ~MODE_MASK;     // Clear mode field
  hw_timer->TAMR  |= MODE_ONESHOT;   // Use one-shot mode
  hw_timer->TAILR  = load_val;       // Interrupt interval (timer ticks)
  hw_timer->IMR   |= TA_INT_BIT;     // Enable interrupt
  hw_timer->CTL   |= TAEN_BIT;       // Enable
}

// Turn off timer
static inline void disable_hw_timer(TIMER_Type *hw_timer)
{
  hw_timer->CTL &= ~TAEN_BIT; // Disable
}


/*
 * Timer ISRs - These Names Must Not Be Changed!!
 */

// Intermediate Timer
void Timer0A_IRQHandler(void)
{
  // Check for correct interrupt
  if (INT_TIMER->MIS & TA_INT_BIT){
    // Clear interrupt signal
    NVIC_ClearPendingIRQ(Timer0A_IRQn);
    INT_TIMER->ICR |= TA_INT_BIT;

    // Set the intermediate flag
    sw_timer_ref->int_expired = 1;
  }
}

// Final Timer
void Timer1A_IRQHandler(void)
{
  // Check for correct interrupt
  if (FIN_TIMER->MIS & TA_INT_BIT){
    // Clear interrupt signal
    NVIC_ClearPendingIRQ(Timer1A_IRQn);
    FIN_TIMER->ICR |= TA_INT_BIT;

    // Set the final flag
    sw_timer_ref->fin_expired = 1;

    // Set global flag
    fin_timer_event = 1;
  }
}

// Sync Timer
void Timer2A_IRQHandler(void)
{
  // Check for correct interrupt
  if (SYNC_TIMER->MIS & TA_INT_BIT){
    // Clear interrupt signal
    NVIC_ClearPendingIRQ(Timer2A_IRQn);
    SYNC_TIMER->ICR |= TA_INT_BIT;

    // Set global flag
    sync_timer_event = 1;
  }
}


/*
 * External Functions
 */

// Callback used by mbedtls to set a timer
void timers_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms)
{
  struct dtls_timers *sw_timer;
  uint32_t int_load_val;
  uint32_t fin_load_val;

  // Immediately disable running HW timers
  disable_hw_timer(INT_TIMER);
  disable_hw_timer(FIN_TIMER);

  // Clear interrupt state
  fin_timer_event = 0;

  // Configure SW timer state
  sw_timer = (struct dtls_timers *) data;
  sw_timer->int_ms = int_ms;
  sw_timer->fin_ms = fin_ms;
  sw_timer->int_expired = 0;
  sw_timer->fin_expired = 0;

  // Set global reference
  sw_timer_ref = sw_timer;

  // Configure new timer state
  if ((fin_ms != 0) && (fin_ms <= MAX_MS_VAL)){
    // Calculate timer load value
    int_load_val = int_ms * TICKS_PER_MS;
    fin_load_val = fin_ms * TICKS_PER_MS;

    // Finally, configure the HW timer
    config_hw_timer(INT_TIMER, int_load_val);
    config_hw_timer(FIN_TIMER, fin_load_val);
  }
}

// Callback used by mbedtls to check if a timer has expired.
int timers_get_delay(void *data)
{
  struct dtls_timers *sw_timer = (struct dtls_timers *) data;

  if (sw_timer->fin_ms == 0) { // Unconfigured
    return -1;
  } else if (sw_timer->fin_expired) { // Final timer done
    return 2;
  } else if (sw_timer->int_expired) { // Intermediate timer done
    return 1;
  }
  return 0;
}

// Function used by SCUM to configure a synq request timeout
void timers_set_scum_timeout(uint32_t ms)
{
  uint32_t load_val;

  // Immediately disable running HW timers
  disable_hw_timer(SYNC_TIMER);

  // Clear interrupt state
  sync_timer_event = 0;

  // Configure new timer state
  if (ms <= MAX_MS_VAL) {
    // Calculate timer load value
    load_val = ms * TICKS_PER_MS;

    // Finally, configure the HW timer
    config_hw_timer(SYNC_TIMER, load_val);
  }
}