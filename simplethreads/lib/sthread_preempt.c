#include <config.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ucontext.h>
#include "sthread_preempt.h"
#include "sthread_ctx.h"
#include "sthread_user.h"

#ifdef STHREAD_CPU_I386
#include "sthread_switch_i386.h"
#endif

#ifdef STHREAD_CPU_X86_64
#include "sthread_switch_x86_64.h"
#endif

#include <sys/time.h>
#include <sys/timeb.h>
#include <signal.h>

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#define LOCK_UNLOCKED 0
#define LOCK_LOCKED 1

int good_interrupts = 0;
int dropped_interrupts = 0;

int inited = false;

/* defined in the start.c and end.c files respectively */
extern void proc_start();
extern void proc_end();

static sthread_ctx_start_func_t interruptHandler;

void sthread_print_stats() {
  printf("\ngood interrupts: %d\n", good_interrupts);
  printf("dropped interrupts: %d\n", dropped_interrupts);
}

void sthread_init_stats() {
  struct sigaction sa, osa;
  sigset_t mask;

  sa.sa_handler = (void(*)(int)) sthread_print_stats;  // NOLINT
  sa.sa_flags = 0;
  sigemptyset(&mask);
  sa.sa_mask = mask;
  // allow getting interrupts statistics via ctrl-backslash
  sigaction(SIGQUIT, &sa, &osa);
}

void sthread_clock_init(sthread_ctx_start_func_t func, int period) {
  struct itimerval it, temp;

  interruptHandler = func;
  sthread_init_stats();
  it.it_interval.tv_sec = period/1000000;
  it.it_interval.tv_usec = period%1000000;
  it.it_value.tv_sec = period/1000000;
  it.it_value.tv_usec = period%1000000;
  setitimer(ITIMER_REAL, &it, &temp);
}


#ifdef STHREAD_CPU_X86_64
void clock_tick64(int signo, siginfo_t *siginfo, void *context) {
  /* See sigaction(2). ucontext_t is defined in /usr/include/sys/ucontext.h.
   * This code was inspired by
   * http://stackoverflow.com/questions/5397041/getting-the-saved-instruction-pointer-address-from-a-signal-handler.  NOLINT
   * PJH: I printed the ip value obtained here while running test-preempt.c
   * and confirmed that the ip is always somewhere within a range of around
   * 300 instructions, which matches the eip behavior on i386. */
  ucontext_t *uctx = (ucontext_t *)context;
  uint64_t ip = uctx->uc_mcontext.gregs[REG_RIP];

  /* Ensures that the pc is within our system code, not system code (libc): */
  if (ip >= (uint64_t) proc_start &&
      ip < (uint64_t) proc_end &&
      !(ip >= (uint64_t) Xsthread_switch &&
        ip < (uint64_t) Xsthread_switch_end)) {
    sigset_t mask, oldmask;
    good_interrupts++;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    sigprocmask(SIG_UNBLOCK, &mask, &oldmask);
    interruptHandler();
  } else {
    dropped_interrupts++;
  }
}
#else
/* signal handler */
void clock_tick(int sig, struct sigcontext scp) {
  /* Ensures that the pc is within our system code, not system code (libc).
   * The definition of struct sigcontext is in /usr/include/bits/sigcontext.h
   * According to sigaction(2), we're not supposed to be able to access the
   * sigcontext in this way anymore:
   *   Before the introduction of SA_SIGINFO it was also possible to get
   *   some additional information, namely by using a sa_handler with second
   *   argument of type struct sigcontext.  See the relevant kernel sources
   *   for details. This use is obsolete now.
   */
  if (scp.eip >= (uint64_t) proc_start &&
      scp.eip < (uint64_t) proc_end &&
      !(scp.eip >= (uint64_t) Xsthread_switch &&
        scp.eip < (uint64_t) Xsthread_switch_end)) {
    sigset_t mask, oldmask;
    good_interrupts++;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    sigprocmask(SIG_UNBLOCK, &mask, &oldmask);
    interruptHandler();
  } else {
    dropped_interrupts++;
  }
}
#endif

/* Turns interrupts ON and off 
 * Returns the last state of the interrupts
 * LOW = interrupts ON
 * HIGH = interrupts OFF
 */
int splx(int splval) {
  struct sigaction sa, osa;
  sigset_t mask;

  if (!inited) {
    return 0;
  }

  /* Disable interrupts: */
  if (splval == HIGH) {
    sa.sa_handler = SIG_IGN;  // ignore SIGALRM signal
    sa.sa_flags = 0;
  } else {  /* LOW: enable interrupts */
#ifdef STHREAD_CPU_X86_64
    /* SA_SIGINFO indicates that we'll use sa_sigaction, rather than
     * sa_handler. We don't set SA_NODEFER, so we won't receive the
     * signal again before the handler completes. We use SA_RESTART
     * to allow some system calls (such as accept()) to be restarted
     * if they are interrupted by the SIGALRM. */
    sa.sa_flags = SA_SIGINFO|SA_RESTART;
    sa.sa_sigaction = clock_tick64;
#else
    sa.sa_handler = (void (*)(int)) clock_tick;  // NOLINT
    /* let the signal be regenerated before this handler is done */
    /* the SA_RESTART flag allows some system calls (like accept)
       to be restarted if they are interrupted by SIGALRM */
    sa.sa_flags = SA_RESTART;  // was SA_SIGINFO; disabled to get sigcontext
#endif
  }

  /* Don't block any signals while the handler executes. SIGALRM is
   * automatically blocked. */
  sigemptyset(&mask);
  sa.sa_mask = mask;

  sigaction(SIGALRM, &sa, &osa);

  /* Return the previous state of the signal handler: HIGH if we were
   * previously ignoring interrupts, and LOW if interrupts were previously
   * enabled.
   */
  return (osa.sa_handler == SIG_IGN) ? HIGH : LOW;
}

/* start preemption - func will be called every period microseconds */

void sthread_preemption_init(sthread_ctx_start_func_t func, int period) {
#ifndef DISABLE_PREEMPTION
  sthread_clock_init(func, period);
  inited = 1;
  splx(LOW);
#endif
}


/*
 * atomic_test_and_set - using the native compare and exchange on the 
 * Intel x86.
 *
 * Example usage:
 *
 *   lock_t mylock;
 *   while(atomic_test_and_set(&lock)) { } // spin
 *   _critical section_
 *   atomic_clear(&lock); 
 */

#if defined(STHREAD_CPU_I386) || defined(STHREAD_CPU_X86_64)
int atomic_test_and_set(lock_t *l) {
  /* PJH: trying to understand this code... see
   *   http://ibiblio.org/gferg/ldp/GCC-Inline-Assembly-HOWTO.html
   * - AT&T syntax: op-code src dest. (Intel syntax: opcode dst src)
   * - Register names are prefixed by %
   * - Last character of op-code name determines size of operands: suffixes
   *   'b', 'w' and 'l' are byte (8-bit?), word (16-bit?), and long (32-bit?).
   *   In Intel syntax, operands are prefixed with 'byte ptr', 'word ptr',
   *   and 'dword ptr' instead.
   * - Indirect memory references: base register is inside of ().
   *   e.g. %eax is the value inside of register eax, while (%eax) is
   *   the value at the location POINTED TO by register eax! (To specify
   *   the register eax itself, i.e. as a destination, %%eax is used.)
   * - First argument in __asm__ is assembler template. %2 is the 3rd
   *   C expression (in parentheses), the literal value 1. (%3) is the
   *   value pointed to by the 4th C expression, l (the pointer to the
   *   lock_t!).
   * - Second argument is output operands. Each operand is an operand-
   *   constraint string followed by the C expression in parentheses.
   *   Operands are comma-separated. The 'a' (%0) is a "constraint"
   *   that tells GCC to store the operand in register eax. The '='
   *   is a "constraint modifier" that says that eax is the output operand
   *   and is write-only.
   * - Third argument is input operands. "a" (%1, eax) is "initialized"
   *   to 0 (this matters because the cmpxchg instruction has %eax as an
   *   implicit input operand).
   *   The "r" constraints specify that the input values (from the C
   *   expressions in parentheses) can be stored in any register.
   * - CMPXCHG has three operands: a source operand in a register, another
   *   source operand in EAX, and a destination operand. If the values
   *   contained in the DESTINATION operand and the EAX register are equal,
   *   then the destination operand is replaced with the value of the other
   *   (non-EAX) source operand. Otherwise, if the values in the dest and
   *   EAX are not equal, then the value of the dest operand is stored
   *   into EAX.
   *   (search for "Intel software developer manual" to find the manual
   *   that provides this information.)
   * - The "lock" prefix ensures that the instruction is performed
   *   atomically.
   *
   * So, finally, the code below atomically compares the value pointed at by
   * the lock_t *l argument with 0; if *l is 0 (unlocked), then *l is replaced
   * with 1 (locked), otherwise *l remains its original value (probably 1,
   * locked).
   *
   * FOR x86_64: lock_t is just an int, which is still 32-bits (4 bytes)
   * according to my test on a UW CSE Fedora15 Linux VM (1/29/12).
   * lock_t is only accessed/used in the simplethreads code by
   * atomic_test_and_set() and atomic_clear(), in sthread_preempt.h and
   * sthread_preempt.c. The locked (1) and unlocked (0) values for the
   * lock_t are specified as absolutes, so they will match any type.
   * The only question is if the 'l' suffix on cmpxchgl still matches
   * the int type of "(%3)" (which is *l) on x86_64. The answer to this
   * question probably lies with the GNU Assembler documentation, and
   * not the Intel software developer's manual...
   * This page (http://www.x86-64.org/documentation/assembly.html) says
   * that a 'q' suffix is used for a "quad-word" (64-bit) operand, so
   * 'l' should still refer to 32-bit integers...
   * To ensure that the operand and instruction widths match, we've
   * re-defined lock_t to explicitly be a 32-bit (unsigned) value,
   * rather than just an int.
   *
   * "info as" (as is the GNU assembler) says in section 9.13.3.1 that
   * "Mnemonic suffixes of `b', `w', `l' and `q' specify byte (8-bit),
   * word (16-bit), long (32-bit) and quadruple word (64-bit) memory
   * references.
   * Could also check out: http://en.wikibooks.org/wiki/X86_Assembly/GAS_Syntax
   */
  int val;
  __asm__ __volatile__("lock cmpxchgl %2, (%3)"
                       : "=a" (val)
                       : "a" (LOCK_UNLOCKED), "r" (LOCK_LOCKED), "r" (l));
  return val;
}


/*
 * atomic_clear - on the intel x86
 *
 */
void atomic_clear(lock_t *l) {
  /* See the description of atomic_test_and_set(): *l is 0 when
   * unlocked, and *l is 1 when locked. To unlock, we simply set
   * *l to 0; this does not have to be atomic.
   */
  *l = LOCK_UNLOCKED;
}
#endif  // (STHREAD_CPU_I386 || STHREAD_CPU_X86_64)
