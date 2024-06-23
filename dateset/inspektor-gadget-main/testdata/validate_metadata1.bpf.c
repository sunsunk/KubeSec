#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define NAME_MAX 255

const volatile int param;
const int param2;
volatile int param3;

struct event {
	gadget_mntns_id mntns_id;
	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[NAME_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__type(value, struct event);
} events SEC(".maps");

GADGET_TRACER(test, events, event);

// map used to test that a wrong map type can't be used
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, gadget_mntns_id);
	__type(value, __u8);
} myhashmap SEC(".maps");

// map used to test map without BTF
// TODO: It's probably that this support will be removed from ebpf library as it was done in libbpf
// (https://github.com/libbpf/libbpf/issues/272) at that time we'll need to remove it.
struct {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
} map_without_btf SEC("maps") = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.max_entries = 4,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
};

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct syscall_trace_enter *ctx)
{
	struct event event = {};

	event.mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(event.mntns_id))
		return 0;

	event.pid = bpf_get_current_pid_tgid() >> 32;

	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user_str(&event.filename, sizeof(event.filename),
				(const char *)ctx->args[1]);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
