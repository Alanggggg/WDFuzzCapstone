#include "private.h"

extern unsigned char *input;

#define FORKSRV_FD 198
#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)
#define SHM_ENV_VAR "__AFL_SHM_ID"

static unsigned char *afl_area_ptr;
static unsigned int afl_inst_rms = MAP_SIZE;
static char *id_str;
unsigned long prev_loc;

void afl_rewind(unsigned long start) {
    prev_loc = (start >> 4) ^ (start << 8);
    prev_loc &= MAP_SIZE - 1;
    prev_loc >>= 1;
    afl_area_ptr[0] = 1;
}

void afl_instrument_location(unsigned long cur_loc) {
    if (!id_str)
        return;

    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= MAP_SIZE - 1;

    afl_area_ptr[cur_loc ^ prev_loc]++;
    prev_loc = cur_loc >> 1;
}

void afl_instrument_location_edge(unsigned long prev_loc, unsigned long cur_loc) {
    if (!id_str)
        return;
    //cur_loc=10101; prev_loc=01010
    // cur_loc=0000000000001 ^ 1010100000000 = 1010100000001
    // 1010100000001 & 01111111111111111
    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= MAP_SIZE - 1;

    prev_loc = (prev_loc >> 4) ^ (prev_loc << 8);
    prev_loc &= MAP_SIZE - 1;

    afl_area_ptr[cur_loc ^ prev_loc]++;
}

void afl_setup(void) {

    int shm_id;

    id_str = getenv(SHM_ENV_VAR);
    char *inst_r = getenv("AFL_INST_RATIO");

    if (inst_r) {
        unsigned int r = atoi(inst_r);

        if (r > 100)
            r = 100;
        if (!r)
            r = 1;

        afl_inst_rms = MAP_SIZE * r / 100;
    }

    if (id_str) {
        shm_id = atoi(id_str);
        afl_area_ptr = shmat(shm_id, NULL, 0);

        if (afl_area_ptr == (void *)-1)
            exit(1);
        if (inst_r)
            afl_area_ptr[0] = 1;
    }

    unsigned char tmp[4];
    if (write(FORKSRV_FD + 1, tmp, 4) == 4) {
        afl = true;
        afl_instrument_location(module_start + start_offset);
    }
}

void afl_wait(void) {
    unsigned char tmp[4];
    if (read(FORKSRV_FD, tmp, 4) != 4) {
        afl = false;
        return;
    }

    pid_t fakepid = 13371337;
    if (write(FORKSRV_FD + 1, &fakepid, 4) != 4)
        afl = false;
}

void afl_report(bool crash) {
    int32_t status = crash ? SIGABRT : 0;
    if (write(FORKSRV_FD + 1, &status, 4) != 4)
        afl = false;
}
