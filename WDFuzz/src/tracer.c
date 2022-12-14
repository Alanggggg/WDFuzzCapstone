#include "breakpoint.h"
#include "fuzz.h"


#define HYPERCALL_BUFFER    0x1337133713371338
#define HYPERCALL_TESTCASE  0x1337133713371337

static const char *traptype[] = {
        [VMI_EVENT_SINGLESTEP] = "singlestep",
        [VMI_EVENT_CPUID] = "cpuid",
        [VMI_EVENT_INTERRUPT] = "int3",
};

extern bool failure;

static vmi_event_t singlestep_event, cc_event;
static struct table *breakpoints;
static struct node *current_bp;
static addr_t reset_breakpoint;

event_response_t (*handle_event)(vmi_instance_t vmi, vmi_event_t *event);

static void write_coverage(unsigned long address) {
    fprintf(coverage_fp, "0x%lx\n", address);
    fflush(coverage_fp);
}

static event_response_t tracer_cb(vmi_instance_t vmi, vmi_event_t *event) {
    if (trace_pid &&
        VMI_SUCCESS != vmi_dtb_to_pid(vmi, event->x86_regs->cr3 & ~(0xfff), &current_pid))
        printf("Can not get pid!\n");

    if (debug)
        printf("[TRACER %s] 0x%lx. PID: %u Limit: %lu/%lu\n", traptype[event->type],
               event->x86_regs->rip, current_pid, tracer_counter, limit);

    if (VMI_EVENT_SINGLESTEP == event->type) {
        if (reset_breakpoint) {
            access_context_t ctx = {.translate_mechanism = VMI_TM_PROCESS_DTB,
                    .dtb = event->x86_regs->cr3,
                    .addr = reset_breakpoint};
            vmi_write_8(vmi, &ctx, &cc);
            reset_breakpoint = 0;
            return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
        }
        return handle_event(vmi, event);
    }

    event->interrupt_event.reinject = 0;

    if (event->x86_regs->rax == HYPERCALL_BUFFER) {
        if (VMI_FAILURE == vmi_pagetable_lookup(vmi, event->x86_regs->cr3 & ~(0xfff),
                                                event->x86_regs->rbx, &address_pa)) {
            printf("Failed to find physical address of target buffer!\n");
            failure = true;
            return 0;
        }

        input_limit = event->x86_regs->rcx;
        if (input)
            free(input);
        input = malloc(input_limit);

        event->x86_regs->rip += 1;
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    if (event->x86_regs->rax == HYPERCALL_TESTCASE ||
        (start_offset && event->x86_regs->rip == module_start + start_offset)) {
        if (debug)
            printf("VM reached the start address\n");

        coverage_enabled = true;
        harness_pid = current_pid;
        tracer_counter = 0;
        if (!fuzz()) {
            failure = true;
            return 0;
        }

        if (target_offset)
            assert(VMI_SUCCESS == vmi_write_va(vmi, module_start + target_offset, 0, 1, &cc, NULL));
        if (!start_offset) {
            event->x86_regs->rax = 0;
            event->x86_regs->rip += 1;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }

        access_context_t ctx = {.translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = event->x86_regs->cr3,
                .addr = event->x86_regs->rip};
        vmi_write_8(vmi, &ctx, &start_byte);
        reset_breakpoint = module_start + start_offset;
        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    if (coverage_enabled && current_pid == harness_pid)
        tracer_counter++;

    return handle_event(vmi, event);
}

event_response_t handle_event_breakpoints(vmi_instance_t vmi, vmi_event_t *event) {
    if (VMI_EVENT_SINGLESTEP == event->type) {
        if (current_pid == harness_pid) {
            if (mode == EDGE) {
                afl_instrument_location_edge(current_bp->address,
                                             event->x86_regs->rip - module_start);
            }
            if (current_bp->taken_addr + module_start == event->x86_regs->rip &&
                !current_bp->taken) {
                current_bp->taken = true;
                write_coverage(current_bp->address);
                write_coverage(current_bp->taken_addr);
            } else if (current_bp->not_taken_addr + module_start == event->x86_regs->rip &&
                       current_bp->not_taken) {
                current_bp->not_taken = true;
                write_coverage(current_bp->address);
                write_coverage(current_bp->not_taken_addr);
            }
        }

        if ((mode == EDGE && !(current_bp->taken && current_bp->not_taken)))
            assert(VMI_SUCCESS ==
                   vmi_write_va(vmi, current_bp->address + module_start, 0, 1, &cc, NULL));

        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    current_bp = get_address(breakpoints, event->x86_regs->rip - module_start);
    assert(current_bp != NULL);
    assert(VMI_SUCCESS == vmi_write_va(vmi, current_bp->address + module_start, 0, 1,
                                       &current_bp->cf_backup, NULL));
    if (coverage_enabled)
        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;

    return 0;
}

bool setup_trace(vmi_instance_t vmi) {
    if (debug)
        printf("Setup trace\n");

    if (start_offset && VMI_FAILURE == vmi_read_va(vmi, module_start + start_offset, 0, 1, &start_byte, NULL))
        return false;

    if (start_offset && VMI_FAILURE == vmi_write_va(vmi, module_start + start_offset, 0, 1, &cc, NULL))
        return false;

    if (target_offset && VMI_FAILURE == vmi_read_va(vmi, module_start + target_offset, 0, 1, &target_byte, NULL))
        return false;

    handle_event = &handle_event_breakpoints;

    if (breakpoints == NULL) {
        FILE *fp = fopen(bp_file, "r");
        assert(fp);

        breakpoints = create_table(0x1000);

        char buf[1024];
        while (fgets(buf, 1024, fp)) {
            char *line = strtok(buf, "\n");

            unsigned long address = strtoul(strtok(line, ","), NULL, 16);
            unsigned long taken_addr = strtoul(strtok(NULL, ","), NULL, 16);
            unsigned long not_taken_addr = strtoul(strtok(NULL, ","), NULL, 16);

            unsigned char backup;

            assert(VMI_SUCCESS ==
                   vmi_read_va(vmi, address + module_start, 0, 1, &backup, NULL));
            insert_breakpoint(breakpoints, address, taken_addr, not_taken_addr, backup);
        }

        fclose(fp);
    }

    for (int pos = 0; pos < breakpoints->size; pos++) {
        struct node *node = breakpoints->nodes[pos];
        while (node) {
            if (mode == EDGE && !(node->taken && node->not_taken))
                assert(VMI_SUCCESS ==
                       vmi_write_va(vmi, node->address + module_start, 0, 1, &cc, NULL));
            node = node->next;
        }
    }
    char mask = 0;
    for (unsigned char i = 0; i < vmi_get_num_vcpus(vmi); i++)
        mask |= 1 << i;
    SETUP_SINGLESTEP_EVENT(&singlestep_event, mask, tracer_cb, 0);
    SETUP_INTERRUPT_EVENT(&cc_event, tracer_cb);
    if (VMI_FAILURE == vmi_register_event(vmi, &singlestep_event))
        return false;

    if (VMI_FAILURE == vmi_register_event(vmi, &cc_event))
        return false;

    if (debug)
        printf("Setup trace finished\n");

    return true;
}


void close_trace(vmi_instance_t vmi) {
    vmi_clear_event(vmi, &singlestep_event, NULL);
    vmi_clear_event(vmi, &cc_event, NULL);

    if (start_offset && start_byte != 0x90)
        vmi_write_va(vmi, module_start + start_offset, 0, 1, &start_byte, NULL);

    if (target_offset)
        vmi_write_va(vmi, module_start + target_offset, 0, 1, &target_byte, NULL);

    for (int i = 0; i < 0x1000; i++) {
        struct node *node = breakpoints->nodes[i];
        while (node) {
            vmi_write_va(vmi, node->address, 0, 1, &node->cf_backup, NULL);
            node = node->next;
        }
    }

    if (debug)
        printf("Closing tracer\n");
}

bool init_tracer(vmi_instance_t vmi) {
    if (!setup_trace(vmi))
        return false;

    return true;
}

void teardown() {
    close_trace(vmi);
    free(input);
    fclose(coverage_fp);
}
