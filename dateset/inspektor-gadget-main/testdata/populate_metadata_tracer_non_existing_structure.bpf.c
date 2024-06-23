#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>

// map used to test wrong value type
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

GADGET_TRACER(test, events, non_existing_type);

char LICENSE[] SEC("license") = "GPL";
