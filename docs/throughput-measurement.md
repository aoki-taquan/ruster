# Throughput measurement support

The privileged veth throughput tests use measurement-only code included from
`crates/bench/src/throughput_measurement.rs`.  It is not linked into the
product packet path.  The veth harness always reports
`hardware_acceptance=false`; its values exercise the measurement mechanism,
not physical-NIC acceptance.

## `perf_event_open` ABI probe

The `perf_event_open(2)` syscall number and `struct perf_event_attr` layout
are measured from the installed Linux kernel headers.  They are not inferred
from a Rust-side guess.  The probe was compiled on the x86_64 host with:

```sh
cc -std=c11 -Wall -Wextra -Werror -x c -o /tmp/ruster-perf-abi-probe - <<'EOF'
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#define PRINT_OFFSET(member) printf("offsetof(%s)=%zu\n", #member, offsetof(struct perf_event_attr, member))

int main(void) {
    printf("__NR_perf_event_open=%ld\n", (long)__NR_perf_event_open);
    printf("sizeof(struct perf_event_attr)=%zu\n", sizeof(struct perf_event_attr));
    struct perf_event_attr flags_probe = {0};
    memset(&flags_probe, 0, sizeof flags_probe);
    flags_probe.disabled = 1;
    size_t flags_storage_offset = sizeof flags_probe;
    const unsigned char *flags_bytes = (const unsigned char *)&flags_probe;
    for (size_t index = 0; index < sizeof flags_probe; ++index) {
        if (flags_bytes[index] != 0) {
            flags_storage_offset = index;
            break;
        }
    }
    if (flags_storage_offset == sizeof flags_probe) {
        fprintf(stderr, "disabled bit did not set a storage byte\n");
        return 1;
    }
    printf("flags_storage_offset=%zu\n", flags_storage_offset);
    PRINT_OFFSET(type);
    PRINT_OFFSET(size);
    PRINT_OFFSET(config);
    PRINT_OFFSET(sample_period);
    PRINT_OFFSET(sample_type);
    PRINT_OFFSET(read_format);
    PRINT_OFFSET(wakeup_events);
    PRINT_OFFSET(bp_type);
    PRINT_OFFSET(config1);
    PRINT_OFFSET(config2);
    PRINT_OFFSET(branch_sample_type);
    PRINT_OFFSET(sample_regs_user);
    PRINT_OFFSET(sample_stack_user);
    PRINT_OFFSET(clockid);
    PRINT_OFFSET(sample_regs_intr);
    PRINT_OFFSET(aux_watermark);
    PRINT_OFFSET(sample_max_stack);
    PRINT_OFFSET(aux_sample_size);
    PRINT_OFFSET(sig_data);
    PRINT_OFFSET(config3);
    printf("PERF_TYPE_HARDWARE=%u\n", PERF_TYPE_HARDWARE);
    printf("PERF_COUNT_HW_CPU_CYCLES=%u\n", PERF_COUNT_HW_CPU_CYCLES);
    printf("PERF_COUNT_HW_CACHE_REFERENCES=%u\n", PERF_COUNT_HW_CACHE_REFERENCES);
    printf("PERF_COUNT_HW_CACHE_MISSES=%u\n", PERF_COUNT_HW_CACHE_MISSES);
    printf("PERF_FORMAT_TOTAL_TIME_ENABLED=%llu\n",
           (unsigned long long)PERF_FORMAT_TOTAL_TIME_ENABLED);
    printf("PERF_FORMAT_TOTAL_TIME_RUNNING=%llu\n",
           (unsigned long long)PERF_FORMAT_TOTAL_TIME_RUNNING);
    printf("PERF_FORMAT_GROUP=%llu\n",
           (unsigned long long)PERF_FORMAT_GROUP);
    printf("combined_read_format=%llu\n",
           (unsigned long long)(PERF_FORMAT_GROUP |
                                PERF_FORMAT_TOTAL_TIME_ENABLED |
                                PERF_FORMAT_TOTAL_TIME_RUNNING));
    printf("PERF_EVENT_READ_FORMAT=%#llx\n",
           (unsigned long long)(PERF_FORMAT_GROUP |
                                PERF_FORMAT_TOTAL_TIME_ENABLED |
                                PERF_FORMAT_TOTAL_TIME_RUNNING));
    printf("PERF_IOC_FLAG_GROUP=%lu\n",
           (unsigned long)PERF_IOC_FLAG_GROUP);
    printf("PERF_EVENT_IOC_ENABLE=%#lx\n", (unsigned long)PERF_EVENT_IOC_ENABLE);
    printf("PERF_EVENT_IOC_DISABLE=%#lx\n", (unsigned long)PERF_EVENT_IOC_DISABLE);
    printf("PERF_EVENT_IOC_RESET=%#lx\n", (unsigned long)PERF_EVENT_IOC_RESET);
    return 0;
}
EOF
/tmp/ruster-perf-abi-probe
```

The command above produced:

```text
__NR_perf_event_open=298
sizeof(struct perf_event_attr)=136
flags_storage_offset=40
offsetof(type)=0
offsetof(size)=4
offsetof(config)=8
offsetof(sample_period)=16
offsetof(sample_type)=24
offsetof(read_format)=32
offsetof(wakeup_events)=48
offsetof(bp_type)=52
offsetof(config1)=56
offsetof(config2)=64
offsetof(branch_sample_type)=72
offsetof(sample_regs_user)=80
offsetof(sample_stack_user)=88
offsetof(clockid)=92
offsetof(sample_regs_intr)=96
offsetof(aux_watermark)=104
offsetof(sample_max_stack)=108
offsetof(aux_sample_size)=112
offsetof(sig_data)=120
offsetof(config3)=128
PERF_TYPE_HARDWARE=0
PERF_COUNT_HW_CPU_CYCLES=0
PERF_COUNT_HW_CACHE_REFERENCES=2
PERF_COUNT_HW_CACHE_MISSES=3
PERF_FORMAT_TOTAL_TIME_ENABLED=1
PERF_FORMAT_TOTAL_TIME_RUNNING=2
PERF_FORMAT_GROUP=8
combined_read_format=11
PERF_EVENT_READ_FORMAT=0xb
PERF_IOC_FLAG_GROUP=1
PERF_EVENT_IOC_ENABLE=0x2400
PERF_EVENT_IOC_DISABLE=0x2401
PERF_EVENT_IOC_RESET=0x2403
```

The Rust `#[repr(C)]` definition has the measured size 136 and compile-time
offset assertions for all fields above, including `config1=56` and
`config2=64`.  The format values above are used as the measured combined
`read_format=11` (`PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED |
PERF_FORMAT_TOTAL_TIME_RUNNING`), and the group ioctl flag is the measured
`PERF_IOC_FLAG_GROUP=1`.  The x86_64 implementation calls
`syscall(__NR_perf_event_open, &attr, 0, -1, group_fd, 0)` with the arguments
after `&attr` being `pid=0, cpu=-1, group_fd, flags=0`:
pid 0 selects the current receiving test thread, cpu -1 permits that thread's
selected CPU, group_fd is -1 for the leader and the leader fd for each
secondary event, and flags is zero.  Cache references and cache misses use
the leader fd as `group_fd`, so all successfully opened events are in one
group.  The group read is the fixed no-ID layout
`nr,time_enabled,time_running,values[]`; the harness verifies the exact byte
length and `nr`, maps values in successful-open order, and scales each raw
count by `time_enabled/time_running` using checked arithmetic.  A zero
`time_running`, invalid timing, group scheduling error, or short read leaves
the affected results `unmeasured`.  Open, control, read, and close failures
are emitted to stderr and are never rendered as zero.

## Latency and placement semantics

Each preallocated sender batch slot receives its own `CLOCK_MONOTONIC`
timestamp before `sendmmsg(2)`.  The receiving test thread reads the timestamp
from the borrowed frame and records the one-way difference with the same
`CLOCK_MONOTONIC` domain.  If consecutive clock reads are equal (a coarse
clock tick), the harness adds a one-nanosecond tie-break to the last
`CLOCK_MONOTONIC`-derived value so every batch slot remains distinct; the
clock reading remains the source of the timestamp.  Percentiles use
nearest-rank with a ceiling rank;
the minimum sample counts are p50=2, p90=10, p99=100, and p99.9=1000.  A
percentile below its minimum is printed as `insufficient_samples`, never as a
numeric value.

The receiving thread calls `sched_setaffinity(2)` and confirms the result with
`sched_getaffinity(2)`.  Verification requires the returned mask to contain
exactly the requested CPU.  NUMA membership is read from node `cpulist`
files.  IRQ affinity is read from `/proc/irq/*/smp_affinity_list` for IRQs
found through the interface's `msi_irqs` directory (with a
`/proc/interrupts` fallback), and RSS counts only physical-device `rx-*`
queues.  A veth has no physical `/device` link, so its synthetic queue is
reported as `not_applicable`; IRQ affinity is likewise `not_applicable` when
no NIC IRQ can be associated.
