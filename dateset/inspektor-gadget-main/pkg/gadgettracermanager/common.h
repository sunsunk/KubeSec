/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef GADGET_TRACER_MANAGER_COMMON_H
#define GADGET_TRACER_MANAGER_COMMON_H

#define MAX_CONTAINERS_PER_NODE 1024

#define NAME_MAX_LENGTH 256

struct container {
	char container_id[NAME_MAX_LENGTH];
	char namespace[NAME_MAX_LENGTH];
	char pod[NAME_MAX_LENGTH];
	char container[NAME_MAX_LENGTH];
};

#endif
