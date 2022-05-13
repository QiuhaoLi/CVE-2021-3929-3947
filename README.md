# CVE-2021-3929-3947

VM escape PoC for [CVE-2021-3929](https://access.redhat.com/security/cve/cve-2021-3929) and [CVE-2021-3947](https://access.redhat.com/security/cve/cve-2021-3947). Educational purposes only.

You can read the **[white paper](https://qiuhao.org/Matryoshka_Trap.pdf)** for more information.

## Environment

```
OS: Ubuntu 21.10
Linux: 5.13.0
gcc: 11.2.0
glibc: 2.34
glib: 2.68.4
QEMU: 6.1.0
Guest OS: Ubuntu 21.04
```

## Commands

### Host

```bash
qemu-system-x86_64 run -machine type=q35,accel=kvm -cpu host \
-m 2G -hda /home/qiuhao/VMs_QEMU/ubuntu21.04/ubuntu21.04.qcow2 \
-device nvme,drive=disk0,serial=1234,cmb_size_mb=64 \
-drive file=null-co://,if=none,format=raw,id=disk0 \
-device ich9-intel-hda -vga qxl -device virtio-serial-pci \
-spice port=5900,disable-ticketing=on \
-device virtserialport,chardev=spicechannel0,name=com.redhat.spice.0 \
-chardev spicevmc,id=spicechannel0,name=vdagent
```

### Guest

```bash
# Disable NVMe's Driver
echo "install nvme /bin/true" | sudo tee -a /etc/modprobe.d/blacklist.conf
sudo update-initramfs -u
sudo reboot

# You should first adjust the hardcoded constants in exp.c
# Add -DCONFIG_DEBUG_MUTEX to gcc if you compile QEMU with --enable-debug
gcc -o exp exp.c
sudo ./exp
# VM escape
```

If exp fails to leak the guest's ram address, restart QEMU and try again.

## Demonstration

https://user-images.githubusercontent.com/45557084/145674292-c32af28f-e206-4b07-aa16-56d8e8dbe27e.mp4

## Acknowledgments

We thank the QEMU community and the Red Hat Product Security team for their professional responses.
