#!/bin/sh
set -eux

# This script does not work unless systemd is available
command -v systemctl >/dev/null 2>&1 || exit 0

# Set up env
for f in .profile .bashrc .zshrc; do
	if ! grep -q "# Lima BEGIN" "${LIMA_CIDATA_HOME}/$f"; then
		cat >>"${LIMA_CIDATA_HOME}/$f" <<EOF
# Lima BEGIN
# Make sure iptables and mount.fuse3 are available
PATH="\$PATH:/usr/sbin:/sbin"
export PATH
EOF
		if compare_version.sh "$(uname -r)" -lt "5.13"; then
			cat >>"${LIMA_CIDATA_HOME}/$f" <<EOF
# fuse-overlayfs is the most stable snapshotter for rootless, on kernel < 5.13
# https://github.com/lima-vm/lima/issues/383
# https://rootlesscontaine.rs/how-it-works/overlayfs/
CONTAINERD_SNAPSHOTTER="fuse-overlayfs"
export CONTAINERD_SNAPSHOTTER
EOF
		fi
		cat >>"${LIMA_CIDATA_HOME}/$f" <<EOF
# Lima END
EOF
		chown "${LIMA_CIDATA_USER}" "${LIMA_CIDATA_HOME}/$f"
	fi
done
# Enable cgroup delegation (only meaningful on cgroup v2)
if [ ! -e "/etc/systemd/system/user@.service.d/lima.conf" ]; then
	mkdir -p "/etc/systemd/system/user@.service.d"
	cat >"/etc/systemd/system/user@.service.d/lima.conf" <<EOF
[Service]
Delegate=yes
EOF
fi
systemctl daemon-reload

# Set up sysctl
sysctl_conf="/etc/sysctl.d/99-lima.conf"
if [ ! -e "${sysctl_conf}" ]; then
	if [ -e "/proc/sys/kernel/unprivileged_userns_clone" ]; then
		echo "kernel.unprivileged_userns_clone=1" >>"${sysctl_conf}"
	fi
	echo "net.ipv4.ping_group_range = 0 2147483647" >>"${sysctl_conf}"
	echo "net.ipv4.ip_unprivileged_port_start=0" >>"${sysctl_conf}"
	sysctl --system
fi

# Set up subuid
for f in /etc/subuid /etc/subgid; do
	grep -qw "${LIMA_CIDATA_USER}" $f || echo "${LIMA_CIDATA_USER}:100000:65536" >>$f
done

# Start systemd session
systemctl start systemd-logind.service
loginctl enable-linger "${LIMA_CIDATA_USER}"
