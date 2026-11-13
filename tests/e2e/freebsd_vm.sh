#!/bin/sh
# Runs the unit tests and tests/e2e/bsd_divert.sh in an official FreeBSD VM
# image (BASIC-CLOUDINIT, from download.freebsd.org) under qemu with KVM.
#
# A NoCloud seed ISO (label cidata) carries the binaries cross-built for
# FreeBSD, the repository's tests/ and a user-data script, which FreeBSD's
# nuageinit runs once at rc.local time of the first boot. The script writes
# to the serial port and powers the VM off; this side reads the result from
# the serial log. No network, no packages: the base system has what the
# test needs.
#
# Usage: tests/e2e/freebsd_vm.sh IMAGE.qcow2 BUILD_DIR   (BUILD_DIR holds geneva
# and geneva-tests built for FreeBSD; TIMEOUT seconds, default 1500)
set -eu
IMG=$1
B=${2%/}
TIMEOUT=${TIMEOUT:-1500}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

[ -x "$B/geneva" ] && [ -x "$B/geneva-tests" ] || { echo "no $B/geneva and $B/geneva-tests"; exit 1; }
mkdir "$W/iso"
tar -cf "$W/iso/payload.tar" tests "$B/geneva" "$B/geneva-tests"
printf 'instance-id: geneva-ci\nlocal-hostname: geneva-ci\n' > "$W/iso/meta-data"
cat > "$W/iso/user-data" <<EOF
#!/bin/sh
exec > /dev/ttyu0 2>&1
echo "GENEVA-VM: start \$(uname -a)"
mkdir -p /mnt/ci
mount -t cd9660 /dev/iso9660/[cC][iI][dD][aA][tT][aA] /mnt/ci || mount -t cd9660 /dev/cd0 /mnt/ci
mkdir -p /root/g && tar -xf /mnt/ci/payload.tar -C /root/g && cd /root/g || { echo "GENEVA-VM: done rc=9"; shutdown -p now; exit; }
rc=0
echo "GENEVA-VM: unit tests"
./$B/geneva-tests || rc=1
echo "GENEVA-VM: e2e"
sh tests/e2e/bsd_divert.sh $B/geneva || rc=1
echo "GENEVA-VM: done rc=\$rc"
shutdown -p now
EOF
genisoimage -quiet -V cidata -J -r -o "$W/seed.iso" "$W/iso"

# a copy-on-write overlay keeps the downloaded image as it is
qemu-img create -q -f qcow2 -F qcow2 -b "$(realpath "$IMG")" "$W/disk.qcow2"
accel=tcg
[ -w /dev/kvm ] && accel=kvm
echo "booting $(basename "$IMG") ($accel)"
timeout "$TIMEOUT" qemu-system-x86_64 -machine q35,accel=$accel -m 2048 -smp 2 \
    -display none -monitor none -serial "file:$W/console.log" \
    -drive file="$W/disk.qcow2",if=virtio,format=qcow2 \
    -drive file="$W/seed.iso",media=cdrom,format=raw \
    -netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0 || echo "qemu: exit $?"
# what the script printed (the console's boot messages too, when it is the
# serial one)
tr -d '\r' < "$W/console.log" | sed -n '/GENEVA-VM: start/,$p'
grep -q "GENEVA-VM: done rc=0" "$W/console.log" || {
    grep -q "GENEVA-VM: start" "$W/console.log" || { echo "-- the script did not start; the serial log:"; tr -d '\r' < "$W/console.log" | tail -80; }
    exit 1
}
