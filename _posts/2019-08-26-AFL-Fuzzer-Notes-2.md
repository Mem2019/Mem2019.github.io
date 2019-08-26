---
layout: post
title:  "AFL Reading Notes 2: Virgin Bits, Calibration and Queue Culling"
date:   2019-08-26 00:00:00 +0000
categories: jekyll update
---

## 0x00 Overview

This is the second part of my notes about AFL source code. Firstly I will discuss virgin bits, which is used to record bits in `trace_bits` of all executions that are never touched. (e.i. always 0) Secondly I will discuss calibration, which is called when a new test case is added to queue. Finally queue culling, which is used to choose the favored test cases in the queue to mutate and fuzz, will be discussed.

## 0x01 Virgin Bits

Such information is recorded in a global variable `u8 virgin_bits[MAP_SIZE]`, which has same size as `trace_bits` shared memory. Initially all of its bits are `1`. Bit 1 suggests that corresponding bits in `trace_bits` is always 0 in all past execution; bit 0 suggests that corresponding bits in `trace_bits` is sometimes set to 1 in one or more previous execution(s).

### `has_new_bits`

This function is used to update `virgin_bits` and return the state about the new coverage.

```c
/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

static inline u8 has_new_bits(u8* virgin_map) {

#ifdef __x86_64__ // use 64-bit pointer in 64-bit OS

  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3); // number of iteration

#else

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */

  u8   ret = 0;

  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */
    // `unlikely` and `likely` are simply compiler hints
    // so we can ignore it
    if (unlikely(*current) && unlikely(*current & *virgin)) {
    // non-zero (*current) means corresponding path is hitted
    // non-zero (*current & *virgin)
    // means there is an untouched bit being touched now
      if (likely(ret < 2)) {
      // try to update ret only if ret can be a higher value
      // if ret == 2, we don't want ret to be reassigned to 1
        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef __x86_64__

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        // if there is a untouched byte being touched now
        // it will mean there is a new path being covered
        else ret = 1;
        // otherwise, the changes are hit counts only
#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
        else ret = 1;

#endif /* ^__x86_64__ */

      }

      *virgin &= ~*current;
      // clear bits in virgin where corresponding bits in *current is 1
    }

    current++;
    virgin++;

  }

  if (ret && virgin_map == virgin_bits) bitmap_changed = 1;

  return ret;

}
```

## 0x02 Calibration

Function `calibrate_case` is function used to perform calibration.

```c
/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                         u32 handicap, u8 from_queue) {

  static u8 first_trace[MAP_SIZE];
  // I don't really think `static` makes any difference here
  // maybe allocating memory with size MAP_SIZE on stack is too big

  u8  fault = 0, new_bits = 0, var_detected = 0,
      first_run = (q->exec_cksum == 0);
      // if checksum is 0,
      // this function is going to be the first run.
      // probability that `cksum` coincides to 0 is too low.

  u64 start_us, stop_us;

  s32 old_sc = stage_cur, old_sm = stage_max;
  u32 use_tmout = exec_tmout;
  u8* old_sn = stage_name;
  // save old globals

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || resuming_fuzz)
    use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                    exec_tmout * CAL_TMOUT_PERC / 100);
    // opdate timeout value for some cases, not really important

  q->cal_failed++;

  stage_name = "calibration";
  stage_max  = fast_cal ? 3 : CAL_CYCLES;
  // update globals stage name and max

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
    init_forkserver(argv);
  // init forkserver for the first time this function is run

  if (q->exec_cksum) memcpy(first_trace, trace_bits, MAP_SIZE);
  // if cksum is not 0, which means the case has been executed
  // then we can just use `trace_bits` global
  // last execution must uses case that `q` represents
  // otherwise `trace_bits` may not represent the same case

  start_us = get_cur_time_us();

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 cksum;

    if (!first_run && !(stage_cur % stats_update_freq)) show_stats();

    write_to_testcase(use_mem, q->len);
    fault = run_target(argv, use_tmout);
    // run the target using the given test case

    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (stop_soon || fault != crash_mode) goto abort_calibration;
    // this will be true if there is any fault
    if (!dumb_mode && !stage_cur && !count_bytes(trace_bits)) {
      fault = FAULT_NOINST; // no instrumentation detected
      goto abort_calibration;
    }// this cases rarely occurs during fuzzing

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
    // calculate the cksum of new execution trace

    if (q->exec_cksum != cksum) {
    // if the new cksum is different from ckum in `q`
      u8 hnb = has_new_bits(virgin_bits);
      if (hnb > new_bits) new_bits = hnb;
      // if there is new bits in `trace_bits` being set
      // implemented using a `virgin_bits`

      if (q->exec_cksum) {
        // if trace differ in different executions
        u32 i;

        for (i = 0; i < MAP_SIZE; i++) {

          if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {
            var_bytes[i] = 1;
            // record newly occur var_bytes
            // used to record varying paths among executions
            stage_max    = CAL_CYCLES_LONG;
            // modify stage_max
          }

        }

        var_detected = 1;

      } else {
        // if this is the first execution
        q->exec_cksum = cksum;
        memcpy(first_trace, trace_bits, MAP_SIZE);
        // update cksum and first_trace
      }

    }

  }

  stop_us = get_cur_time_us();
  total_cal_us     += stop_us - start_us;
  total_cal_cycles += stage_max;
  // update time and cycles, not interesting

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  q->exec_us     = (stop_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits); // num of non-zero bytes
  q->handicap    = handicap;
  q->cal_failed  = 0;
  // update fields in `q`
  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;
  // update global metrics
  update_bitmap_score(q);
  // relative to queue culling, to be covered soon
  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;
  // in the first run, if there is no fault, and no new bit is produced,
  // it means this test case does not provide any new path state,
  // so we set return value to FAULT_NOBITS

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    queued_with_cov++;
  }// if new path is covered, set some variable

  /* Mark variable paths. */

  if (var_detected) {
  // if path is different among executions
    var_byte_count = count_bytes(var_bytes);
    // update var_byte_count
    if (!q->var_behavior) {
      mark_as_variable(q);
      // set var_behavior to 1, 
      // and create a symbolic link
      queued_variable++;
      // increment global counter
    }

  }

  stage_name = old_sn;
  stage_cur  = old_sc;
  stage_max  = old_sm;
  // recover global variables

  if (!first_run) show_stats();

  return fault;

}
```

For example, this function is called in `perform_dry_run`.

```c
/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */

static void perform_dry_run(char** argv) {

  struct queue_entry* q = queue;
  u32 cal_failures = 0;
  u8* skip_crashes = getenv("AFL_SKIP_CRASHES");

  while (q) {

    u8* use_mem;
    u8  res;
    s32 fd;

    u8* fn = strrchr(q->fname, '/') + 1;

    ACTF("Attempting dry run with '%s'...", fn);

    fd = open(q->fname, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", q->fname);

    use_mem = ck_alloc_nozero(q->len);

    if (read(fd, use_mem, q->len) != q->len)
      FATAL("Short read from '%s'", q->fname);

    close(fd);

    res = calibrate_case(argv, q, use_mem, 0, 1);
    ck_free(use_mem);

    if (stop_soon) return;

    if (res == crash_mode || res == FAULT_NOBITS)
      SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST,
           q->len, q->bitmap_size, q->exec_us);

    switch (res) {

      case FAULT_NONE:

        if (q == queue) check_map_coverage();

        if (crash_mode) FATAL("Test case '%s' does *NOT* crash", fn);
		// crash_mode == FAULT_NONE == 0 for general fuzzing
        break;
        /* ...other fault handlings...*/
    }
    
    if (q->var_behavior) WARNF("Instrumentation output varies across runs.");

    q = q->next;

  }
  /*......*/
  OKF("All test cases processed.");
}
```

## 0x03 Queue Culling

As the fuzzing goes, total number of test cases in the queue increases. However, in order to hit all paths being covered in these queue, only a subset of these test cases are needed. By culling the queue, AFL tries choose the optimal such subset that the file execution time and file size are minimized.

There is a global variable `struct queue_entry* top_rated[MAP_SIZE]`, which is used to record the optimal test case that is able to cover a particular path (e.i. the index of the array). This `top_rated` is updated by function `update_bitmap_score`.

```c
/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has a more favorable speed x size factor. */

static void update_bitmap_score(struct queue_entry* q) {

  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in trace_bits[], see if there is a previous winner,
     and how it compares to us. */

  for (i = 0; i < MAP_SIZE; i++)
    // again, assumption is trace_bits must represent execution of `q`
    if (trace_bits[i]) {

       if (top_rated[i]) {
         // if there is already another test case that covers this path
         /* Faster-executing or smaller test cases are favored. */

         if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;
         // if current factor is not more favorable than original one, skip
         /* Looks like we're going to win. Decrease ref count for the
            previous winner, discard its trace_bits[] if necessary. */

         if (!--top_rated[i]->tc_ref) {
           ck_free(top_rated[i]->trace_mini);
           top_rated[i]->trace_mini = 0;
         }// decrement reference counting,
         // this field is used in this function only
       }

       /* Insert ourselves as the new winner. */

       top_rated[i] = q;
       q->tc_ref++;
       // update element and increment ref counter
       if (!q->trace_mini) {
         q->trace_mini = ck_alloc(MAP_SIZE >> 3);
         minimize_bits(q->trace_mini, trace_bits);
       }// trace_mini only record path coverage, ignoring counts

       score_changed = 1;

     }

}
```

To sum up, for all paths being covered by `trace_bits`, this function updates `top_rated[i]` to `q` if necessary. From my perspective, this algorithm is greedy and not optimal. For example, assuming file size to be same, if 3 paths can both be covered by 3 test cases and 1 test case, and the 3 test cases takes `0.03 * 3 = 0.09` seconds but that 1 test case only takes `0.04` seconds, the algorithm will choose that 3 test cases, but that one test case seems to be more optimal. However, it is hard to come up with a better algorithm, and current algorithm is already close to the optimal solution. Maybe this is a NPC problem and cannot be solved efficiently.

Another function is `cull_queue`, which is used to select a favored subset.

```c
/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

static void cull_queue(void) {

  struct queue_entry* q;
  static u8 temp_v[MAP_SIZE >> 3];
  // static because memory is too large to be allocated on stack
  u32 i;

  if (dumb_mode || !score_changed) return;
  // perform queue culling only if score is changed, TODO

  score_changed = 0;

  memset(temp_v, 255, MAP_SIZE >> 3);
  // all bits of temp_v are 1 initially

  queued_favored  = 0;
  pending_favored = 0;
  // reset globals to 0
  q = queue;

  while (q) {
    q->favored = 0;
    q = q->next;
  }// reset all `favored` fields to 0

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */

  for (i = 0; i < MAP_SIZE; i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--)
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];
      // for all path that can be covered by this test case
      // remove them from temp_v
      // so that other test cases that cover same path
      // don't have to be considered

      top_rated[i]->favored = 1;
      queued_favored++;
      // mark as favored

      if (!top_rated[i]->was_fuzzed) pending_favored++;
      // if not fuzzed, TODO
    }

  q = queue;

  while (q) {
    mark_as_redundant(q, !q->favored);
    // unfavored entries are redundant
    q = q->next;
  }

}
```

After this operation, `favored` fields of some element of `queue` will be set to represent the subset. Here the subset selection is sequential and done in a for loop, but maybe random selection is a better approach so that equal chance will be given to every element in the `queue` regardless their order in the `queue`.