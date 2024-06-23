#include "kvm/ioport.h"

#include "kvm/kvm.h"
#include "kvm/util.h"
#include "kvm/rbtree-interval.h"
#include "kvm/mutex.h"

#include <linux/kvm.h>	/* for KVM_EXIT_* */
#include <linux/types.h>

#include <stdbool.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

#define ioport_node(n) rb_entry(n, struct ioport, node)

static DEFINE_MUTEX(ioport_lock);

static struct rb_root		ioport_tree = RB_ROOT;

static struct ioport *ioport_search(struct rb_root *root, u64 addr)
{
	struct rb_int_node *node;

	node = rb_int_search_single(root, addr);
	if (node == NULL)
		return NULL;

	return ioport_node(node);
}

static int ioport_insert(struct rb_root *root, struct ioport *data)
{
	return rb_int_insert(root, &data->node);
}

static void ioport_remove(struct rb_root *root, struct ioport *data)
{
	rb_int_erase(root, &data->node);
}

static struct ioport *ioport_get(struct rb_root *root, u64 addr)
{
	struct ioport *ioport;

	mutex_lock(&ioport_lock);
	ioport = ioport_search(root, addr);
	if (ioport)
		ioport->refcount++;
	mutex_unlock(&ioport_lock);

	return ioport;
}

/* Called with ioport_lock held. */
static void ioport_unregister(struct rb_root *root, struct ioport *data)
{
	device__unregister(&data->dev_hdr);
	ioport_remove(root, data);
	free(data);
}

static void ioport_put(struct rb_root *root, struct ioport *data)
{
	mutex_lock(&ioport_lock);
	data->refcount--;
	if (data->remove && data->refcount == 0)
		ioport_unregister(root, data);
	mutex_unlock(&ioport_lock);
}

#ifdef CONFIG_HAS_LIBFDT
static void generate_ioport_fdt_node(void *fdt,
				     struct device_header *dev_hdr,
				     void (*generate_irq_prop)(void *fdt,
							       u8 irq,
							       enum irq_type))
{
	struct ioport *ioport = container_of(dev_hdr, struct ioport, dev_hdr);
	struct ioport_operations *ops = ioport->ops;

	if (ops->generate_fdt_node)
		ops->generate_fdt_node(ioport, fdt, generate_irq_prop);
}
#else
static void generate_ioport_fdt_node(void *fdt,
				     struct device_header *dev_hdr,
				     void (*generate_irq_prop)(void *fdt,
							       u8 irq,
							       enum irq_type))
{
	die("Unable to generate device tree nodes without libfdt\n");
}
#endif

int ioport__register(struct kvm *kvm, u16 port, struct ioport_operations *ops, int count, void *param)
{
	struct ioport *entry;
	int r;

	entry = malloc(sizeof(*entry));
	if (entry == NULL)
		return -ENOMEM;

	*entry = (struct ioport) {
		.node		= RB_INT_INIT(port, port + count),
		.ops		= ops,
		.priv		= param,
		.dev_hdr	= (struct device_header) {
			.bus_type	= DEVICE_BUS_IOPORT,
			.data		= generate_ioport_fdt_node,
		},
		/*
		 * Start from 0 because ioport__unregister() doesn't decrement
		 * the reference count.
		 */
		.refcount	= 0,
		.remove		= false,
	};

	mutex_lock(&ioport_lock);
	r = ioport_insert(&ioport_tree, entry);
	if (r < 0)
		goto out_free;
	r = device__register(&entry->dev_hdr);
	if (r < 0)
		goto out_remove;
	mutex_unlock(&ioport_lock);

	return port;

out_remove:
	ioport_remove(&ioport_tree, entry);
out_free:
	free(entry);
	mutex_unlock(&ioport_lock);
	return r;
}

int ioport__unregister(struct kvm *kvm, u16 port)
{
	struct ioport *entry;

	mutex_lock(&ioport_lock);
	entry = ioport_search(&ioport_tree, port);
	if (!entry) {
		mutex_unlock(&ioport_lock);
		return -ENOENT;
	}
	/* The same reasoning from kvm__deregister_mmio() applies. */
	if (entry->refcount == 0)
		ioport_unregister(&ioport_tree, entry);
	else
		entry->remove = true;
	mutex_unlock(&ioport_lock);

	return 0;
}

static void ioport__unregister_all(void)
{
	struct ioport *entry;
	struct rb_node *rb;
	struct rb_int_node *rb_node;

	rb = rb_first(&ioport_tree);
	while (rb) {
		rb_node = rb_int(rb);
		entry = ioport_node(rb_node);
		ioport_unregister(&ioport_tree, entry);
		rb = rb_first(&ioport_tree);
	}
}

static const char *to_direction(int direction)
{
	if (direction == KVM_EXIT_IO_IN)
		return "IN";
	else
		return "OUT";
}

static void ioport_error(u16 port, void *data, int direction, int size, u32 count)
{
	fprintf(stderr, "IO error: %s port=%x, size=%d, count=%u\n", to_direction(direction), port, size, count);
}

bool kvm__emulate_io(struct kvm_cpu *vcpu, u16 port, void *data, int direction, int size, u32 count)
{
	struct ioport_operations *ops;
	bool ret = false;
	struct ioport *entry;
	void *ptr = data;
	struct kvm *kvm = vcpu->kvm;

	entry = ioport_get(&ioport_tree, port);
	if (!entry)
		goto out;

	ops	= entry->ops;

	while (count--) {
		if (direction == KVM_EXIT_IO_IN && ops->io_in)
				ret = ops->io_in(entry, vcpu, port, ptr, size);
		else if (direction == KVM_EXIT_IO_OUT && ops->io_out)
				ret = ops->io_out(entry, vcpu, port, ptr, size);

		ptr += size;
	}

	ioport_put(&ioport_tree, entry);

out:
	if (ret)
		return true;

	if (kvm->cfg.ioport_debug)
		ioport_error(port, data, direction, size, count);

	return !kvm->cfg.ioport_debug;
}

int ioport__init(struct kvm *kvm)
{
	return ioport__setup_arch(kvm);
}
dev_base_init(ioport__init);

int ioport__exit(struct kvm *kvm)
{
	ioport__unregister_all();
	return 0;
}
dev_base_exit(ioport__exit);
