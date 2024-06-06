---
sidebar_position: 6
sidebar_label: "Evictor"
---

# Evictor

The Evictor is used to automatically migrate HwameiStor volumes in case of node or pod eviction. When a node or pod is evicted as either Planned or Unplanned, the associated HwameiStor volumes, which have a replica on the node, will be detected and migrated out of this node automatically. A scheduler will work for both LVM and Disk volumes.

The Evictor should be deployed with the HA mode in the cluster, which is a best practice for production.
