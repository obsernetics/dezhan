#!/usr/bin/env bash
set -euo pipefail
NAME="$1"; MEM="${2:-4096}"; CPU="${3:-2}"; DISK="${4:-12}"
B=/var/lib/libvirt/images/dezhanbench
BASE=/var/lib/libvirt/images/noble-server-cloudimg-amd64.img
qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$B/$NAME.qcow2" "${DISK}G" >/dev/null
sed "s/__HOST__/$NAME/" /root/dezhan/bench/cloud-init/user-data.tmpl > "$B/$NAME-user-data"
printf 'instance-id: %s\nlocal-hostname: %s\n' "$NAME" "$NAME" > "$B/$NAME-meta-data"
cloud-localds "$B/$NAME-seed.iso" "$B/$NAME-user-data" "$B/$NAME-meta-data"
virt-install --name "$NAME" --memory "$MEM" --vcpus "$CPU" \
  --disk "path=$B/$NAME.qcow2,format=qcow2,bus=virtio" \
  --disk "path=$B/$NAME-seed.iso,device=cdrom" \
  --os-variant ubuntu24.04 --network network=default,model=virtio \
  --graphics none --import --noautoconsole >/dev/null
echo "created $NAME"
