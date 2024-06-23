/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "headers/cgroup.h"
#include "headers/helpers.h"
#include "headers/mesh.h"
#include <linux/bpf.h>
#include <linux/in.h>

// this prog hook linkerd bind OUTPUT_LISTENER
// which will makes the listen address change from 127.0.0.1:4140 to
// 0.0.0.0:4140
#if ENABLE_IPV4
__section("cgroup/bind4") int mb_bind(struct bpf_sock_addr *ctx)
{
#if MESH == ISTIO
    // fix original src from ztunnel to waypoint
    struct cgroup_info cg_info;
    if (!get_current_cgroup_info(ctx, &cg_info)) {
        return 1;
    }
    if ((cg_info.detected_flags & ZTUNNEL_FLAG) &&
        (cg_info.flags & ZTUNNEL_FLAG)) {
        // ztunnel
        __u32 *ztunnel_ip = get_ztunnel_ip();
        if (!ztunnel_ip) {
            debugf("can not get ztunnel pod ip in bind");
            return 1;
        }
        // ztunnel will bind the source pod ip to upstream,
        // we will rollback this operation because we not support TPROXY mode.
        ctx->user_ip4 = ztunnel_ip[3];
        debugf("successfully rewrite ztunnel bind");
    }
    return 1;
#endif
#if MESH != LINKERD
    // only works on linkerd
    return 1;
#endif

    if (ctx->user_ip4 == 0x0100007f &&
        ctx->user_port == bpf_htons(OUT_REDIRECT_PORT)) {
        __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
        if (uid == SIDECAR_USER_ID) {
            // linkerd listen localhost, we have to change the bind address to
            // 0.0.0.0:4140
            printk("change bind address from 127.0.0.1:%d to 0.0.0.0:%d",
                   OUT_REDIRECT_PORT, OUT_REDIRECT_PORT);
            ctx->user_ip4 = 0;
        }
    }
    return 1;
}
#endif

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
