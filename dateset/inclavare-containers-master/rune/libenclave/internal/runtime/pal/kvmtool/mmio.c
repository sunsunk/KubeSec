#include "kvm/kvm.h"
#include "kvm/kvm-cpu.h"
#include "kvm/rbtree-interval.h"
#include "kvm/mutex.h"

#include <stdio.h>
#include <stdlib.h>

#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/err.h>
#include <errno.h>

#define mmio_node(n) rb_entry(n, struct mmio_mapping, node)

static DEFINE_MUTEX(mmio_lock);

struct mmio_mapping {
	struct rb_int_node	node;
	void			(*mmio_fn)(struct kvm_cpu *vcpu, u64 addr, u8 *data, u32 len, u8 is_write, void *ptr);
	void			*ptr;
	u32			refcount;
	bool			remove;
};

static struct rb_root mmio_tree = RB_ROOT;

static struct mmio_mapping *mmio_search(struct rb_root *root, u64 addr, u64 len)
{
	struct rb_int_node *node;

	node = rb_int_search_range(root, addr, addr + len);
	if (node == NULL)
		return NULL;

	return mmio_node(node);
}

/* Find lowest match, Check for overlap */
static struct mmio_mapping *mmio_search_single(struct rb_root *root, u64 addr)
{
	struct rb_int_node *node;

	node = rb_int_search_single(root, addr);
	if (node == NULL)
		return NULL;

	return mmio_node(node);
}

static int mmio_insert(struct rb_root *root, struct mmio_mapping *data)
{
	return rb_int_insert(root, &data->node);
}

static void mmio_remove(struct rb_root *root, struct mmio_mapping *data)
{
	rb_int_erase(root, &data->node);
}

static const char *to_direction(u8 is_write)
{
	if (is_write)
		return "write";

	return "read";
}

static struct mmio_mapping *mmio_get(struct rb_root *root, u64 phys_addr, u32 len)
{
	struct mmio_mapping *mmio;

	mutex_lock(&mmio_lock);
	mmio = mmio_search(root, phys_addr, len);
	if (mmio)
		mmio->refcount++;
	mutex_unlock(&mmio_lock);

	return mmio;
}

/* Called with mmio_lock held. */
static void mmio_deregister(struct kvm *kvm, struct rb_root *root, struct mmio_mapping *mmio)
{
	struct kvm_coalesced_mmio_zone zone = (struct kvm_coalesced_mmio_zone) {
		.addr	= rb_int_start(&mmio->node),
		.size	= 1,
	};
	ioctl(kvm->vm_fd, KVM_UNREGISTER_COALESCED_MMIO, &zone);

	mmio_remove(root, mmio);
	free(mmio);
}

static void mmio_put(struct kvm *kvm, struct rb_root *root, struct mmio_mapping *mmio)
{
	mutex_lock(&mmio_lock);
	mmio->refcount--;
	if (mmio->remove && mmio->refcount == 0)
		mmio_deregister(kvm, root, mmio);
	mutex_unlock(&mmio_lock);
}

int kvm__register_mmio(struct kvm *kvm, u64 phys_addr, u64 phys_addr_len, bool coalesce,
		       void (*mmio_fn)(struct kvm_cpu *vcpu, u64 addr, u8 *data, u32 len, u8 is_write, void *ptr),
			void *ptr)
{
	struct mmio_mapping *mmio;
	struct kvm_coalesced_mmio_zone zone;
	int ret;

	mmio = malloc(sizeof(*mmio));
	if (mmio == NULL)
		return -ENOMEM;

	*mmio = (struct mmio_mapping) {
		.node		= RB_INT_INIT(phys_addr, phys_addr + phys_addr_len),
		.mmio_fn	= mmio_fn,
		.ptr		= ptr,
		/*
		 * Start from 0 because kvm__deregister_mmio() doesn't decrement
		 * the reference count.
		 */
		.refcount	= 0,
		.remove		= false,
	};

	if (coalesce) {
		zone = (struct kvm_coalesced_mmio_zone) {
			.addr	= phys_addr,
			.size	= phys_addr_len,
		};
		ret = ioctl(kvm->vm_fd, KVM_REGISTER_COALESCED_MMIO, &zone);
		if (ret < 0) {
			free(mmio);
			return -errno;
		}
	}
	mutex_lock(&mmio_lock);
	ret = mmio_insert(&mmio_tree, mmio);
	mutex_unlock(&mmio_lock);

	return ret;
}

bool kvm__deregister_mmio(struct kvm *kvm, u64 phys_addr)
{
	struct mmio_mapping *mmio;

	mutex_lock(&mmio_lock);
	mmio = mmio_search_single(&mmio_tree, phys_addr);
	if (mmio == NULL) {
		mutex_unlock(&mmio_lock);
		return false;
	}
	/*
	 * The PCI emulation code calls this function when memory access is
	 * disabled for a device, or when a BAR has a new address assigned. PCI
	 * emulation doesn't use any locks and as a result we can end up in a
	 * situation where we have called mmio_get() to do emulation on one VCPU
	 * thread (let's call it VCPU0), and several other VCPU threads have
	 * called kvm__deregister_mmio(). In this case, if we decrement refcount
	 * kvm__deregister_mmio() (either directly, or by calling mmio_put()),
	 * refcount will reach 0 and we will free the mmio node before VCPU0 has
	 * called mmio_put(). This will trigger use-after-free errors on VCPU0.
	 */
	if (mmio->refcount == 0)
		mmio_deregister(kvm, &mmio_tree, mmio);
	else
		mmio->remove = true;
	mutex_unlock(&mmio_lock);

	return true;
}

bool kvm__emulate_mmio(struct kvm_cpu *vcpu, u64 phys_addr, u8 *data, u32 len, u8 is_write)
{
	struct mmio_mapping *mmio;

	mmio = mmio_get(&mmio_tree, phys_addr, len);
	if (!mmio) {
		if (vcpu->kvm->cfg.mmio_debug)
			fprintf(stderr,	"Warning: Ignoring MMIO %s at %016llx (length %u)\n",
				to_direction(is_write),
				(unsigned long long)phys_addr, len);
		goto out;
	}

	mmio->mmio_fn(vcpu, phys_addr, data, len, is_write, mmio->ptr);
	mmio_put(vcpu->kvm, &mmio_tree, mmio);

out:
	return true;
}
