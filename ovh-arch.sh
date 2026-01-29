#!/bin/bash

TZ="Asia/Bangkok"
DISK="/dev/sdb"
AUTHORIZED_KEYS="https://raw.githubusercontent.com/nyatoru/nyarutoru.github.io/refs/heads/main/authorized_keys"

set -o nounset
set -o errexit
set -o pipefail

# Logging
exec 1> >(tee /tmp/install.log)
exec 2>&1

ACTION="${1:-}"
USERNAME="${2:-}"
PASSWORD="${3:-}"

ipv4_address=""
ipv4_prefix=""
ipv4_gateway=""
ipv6_address=""
ipv6_prefix="128"
ipv6_gateway=""

get_network_info() {
    echo "=== Detecting network configuration ==="
    
    local iface=$(ip -4 route | grep default | sed -e "s/^.*dev \([^ ]*\) .*$/\1/" | head -n1)
    if [ -z "$iface" ]; then
        echo "Could not determine default IPv4 interface." >&2
        exit 1
    fi
    echo "Default interface: $iface"

    local ip_info=$(ip -4 addr show dev "$iface" | grep "inet " | awk '{print $2}' | head -n1)
    if [ -z "$ip_info" ]; then
        echo "Could not determine IPv4 address for interface $iface." >&2
        exit 1
    fi
    ipv4_address=$(echo "$ip_info" | cut -d'/' -f1)
    ipv4_prefix=$(echo "$ip_info" | cut -d'/' -f2)

    ipv4_gateway=$(ip -4 route | grep default | awk '{print $3}' | head -n1)
    if [ -z "$ipv4_gateway" ]; then
        echo "Could not determine default IPv4 gateway." >&2
        exit 1
    fi
    echo "IPv4 Address: $ipv4_address"
    echo "IPv4 Prefix: $ipv4_prefix"
    echo "IPv4 Gateway: $ipv4_gateway"

    echo "Detecting IPv6 configuration..."
    ipv6_address=$(ip -6 route 2>/dev/null | grep -v "^fe80" | grep -v "^ff00" | head -n1 | cut -f1 -d" " || echo "")
    
    if [ -z "$ipv6_address" ] || [ "$ipv6_address" = "::1" ]; then
        echo "Warning: No IPv6 address found"
        ipv6_gateway=""
    else
        echo "IPv6 Address found: $ipv6_address"
        
        if [ -f /etc/network/interfaces.d/50-cloud-init ]; then
            local ipv6_gateway_info=$(grep -i "gateway" /etc/network/interfaces.d/50-cloud-init 2>/dev/null | grep -v "^#" | grep ":" | head -n1 | awk '{print $NF}' || echo "")
            if [ -n "$ipv6_gateway_info" ]; then
                ipv6_gateway=$(echo "$ipv6_gateway_info" | cut -d'/' -f1)
                echo "IPv6 Gateway: $ipv6_gateway"
            else
                echo "Warning: Could not determine IPv6 gateway from cloud-init"
                ipv6_gateway=""
            fi
        else
            echo "Warning: /etc/network/interfaces.d/50-cloud-init not found"
            ipv6_gateway=$(ip -6 route 2>/dev/null | grep "^default" | awk '{print $3}' || echo "")
            if [ -n "$ipv6_gateway" ]; then
                echo "IPv6 Gateway (from routing table): $ipv6_gateway"
            else
                echo "Warning: Could not determine IPv6 gateway"
            fi
        fi
    fi
    
    echo "Network detection complete"
    echo "---"
}

# ฟังก์ชันสำหรับ umount อย่างปลอดภัย
safe_umount() {
    local mount_point="$1"
    local max_attempts=5
    local attempt=1
    
    if ! mountpoint -q "$mount_point" 2>/dev/null; then
        echo "✓ $mount_point is not mounted"
        return 0
    fi
    
    echo "Unmounting $mount_point..."
    
    while [ $attempt -le $max_attempts ]; do
        if umount "$mount_point" 2>/dev/null; then
            echo "✓ Successfully unmounted $mount_point"
            return 0
        fi
        
        echo "Attempt $attempt/$max_attempts: $mount_point is busy, trying lazy umount..."
        
        # ฆ่า process ที่ใช้งาน mount point
        fuser -km "$mount_point" 2>/dev/null || true
        sleep 1
        
        # ลอง umount อีกครั้ง
        if umount "$mount_point" 2>/dev/null; then
            echo "✓ Successfully unmounted $mount_point"
            return 0
        fi
        
        # ถ้ายังไม่ได้ ใช้ lazy umount
        if umount -l "$mount_point" 2>/dev/null; then
            echo "✓ Lazy unmounted $mount_point"
            return 0
        fi
        
        attempt=$((attempt + 1))
        sleep 2
    done
    
    echo "⚠ Warning: Could not cleanly unmount $mount_point, forcing..."
    umount -f "$mount_point" 2>/dev/null || umount -l "$mount_point" 2>/dev/null || true
}

function main() {
    if [[ -z "$ACTION" ]]; then
        echo "Usage: $0 <hostname> <username> <password>"
        echo "Example: $0 myserver john MySecurePass123"
        exit 1
    fi
    
    if [[ -z "$USERNAME" ]]; then
        echo "Error: Username is required"
        echo "Usage: $0 <hostname> <username> <password>"
        exit 1
    fi
    
    if [[ -z "$PASSWORD" ]]; then
        echo "Error: Password is required"
        echo "Usage: $0 <hostname> <username> <password>"
        exit 1
    fi
    
    echo "=== Starting Arch Linux installation ==="
    echo "Target disk: $DISK"
    echo "Hostname: $ACTION"
    echo "Username: $USERNAME"
    echo "Password: [hidden]"
    echo "Kernel: linux-zen"
    
    if [ ! -b "$DISK" ]; then
        echo "Error: Disk $DISK does not exist" >&2
        exit 1
    fi
    
    if mount | grep -q "$DISK"; then
        echo "Warning: $DISK has mounted partitions. Unmounting..."
        umount ${DISK}* 2>/dev/null || true
    fi
    
    get_network_info
    cd /tmp
    
    echo "=== Downloading Arch Linux bootstrap ==="
    curl -fSsL https://mirror.pkgbuild.com/iso/latest/archlinux-bootstrap-x86_64.tar.zst > /tmp/archlinux.tar.zst
    
    if [ ! -s /tmp/archlinux.tar.zst ]; then
        echo "Error: Failed to download Arch Linux bootstrap" >&2
        exit 1
    fi

    echo "=== Preparing disk ==="
    umount ${DISK}* 2>/dev/null || true
    swapoff ${DISK}* 2>/dev/null || true
    wipefs -af "$DISK" 2>/dev/null || true

    echo "=== Partitioning disk ==="
    sgdisk --zap-all "$DISK"
    sgdisk -n 1:2048:+512M -c 1:"EFI System Partition" -t 1:EF00 "$DISK"
    sgdisk -n 2:0:0 --typecode=2:8300 --change-name=2:"Linux Root" "$DISK"
    
    echo "=== Reloading partition table ==="
    partprobe "$DISK" 2>/dev/null || true
    blockdev --rereadpt "$DISK" 2>/dev/null || true
    sleep 3
    
    for i in {1..10}; do
        if [ -b "${DISK}1" ] && [ -b "${DISK}2" ]; then
            echo "✓ Partitions ready"
            break
        fi
        echo "Waiting for partitions... ($i/10)"
        sleep 1
    done
    
    if [ ! -b "${DISK}1" ] || [ ! -b "${DISK}2" ]; then
        echo "Error: Partition devices not found" >&2
        ls -l /dev/sd* >&2
        exit 1
    fi
    
    echo "=== Formatting partitions ==="
    mkfs.fat -F32 "${DISK}1"
    mkfs.ext4 -F "${DISK}2"
    sgdisk -p "$DISK"

    echo "=== Setting up root filesystem ==="
    mkdir -p /mnt
    mount "${DISK}2" /mnt
    
    # Mount EFI partition
    mkdir -p /mnt/boot
    mount "${DISK}1" /mnt/boot
    
    echo "=== Extracting base system ==="
    cd /mnt
    tar xf /tmp/archlinux.tar.zst --strip-components=1 2>&1 | grep -v "Ignoring unknown extended header keyword" || true

    echo "=== Configuring pacman ==="
    cat > /mnt/etc/pacman.d/mirrorlist << 'EOF'
Server = https://mirror.pkgbuild.com/$repo/os/$arch
EOF
    sed -i -e 's/#ParallelDownloads/ParallelDownloads/' /mnt/etc/pacman.conf
    
    echo "=== Preparing chroot environment ==="
    # Copy DNS configuration from host
    cp /etc/resolv.conf /mnt/etc/resolv.conf
    
    mount --bind /dev /mnt/dev
    mount --bind /dev/pts /mnt/dev/pts
    mount -t proc /proc /mnt/proc
    mount -t sysfs /sys /mnt/sys
    mount -t tmpfs /tmp /mnt/tmp
    
    # Create installation script
    cat > /mnt/root/install.sh << 'INSTALLSCRIPT'
#!/bin/bash
set -o errexit
set -o nounset

HOSTNAME="$1"
USERNAME="$2"
PASSWORD="$3"
TZ="Asia/Bangkok"
DISK="/dev/sdb"
AUTHORIZED_KEYS="https://raw.githubusercontent.com/nyatoru/nyarutoru.github.io/refs/heads/main/authorized_keys"

echo "=== Initializing pacman keyring ==="
pacman-key --init
pacman-key --populate archlinux

echo "=== Installing packages ==="
# เปลี่ยนเป็น linux-zen และเพิ่ม linux-zen-headers
pacman -Sy --noconfirm base linux-zen linux-zen-headers linux-firmware openssh sudo

echo "=== Updating system (pacman -Syu) ==="
# อัพเดทระบบให้เป็นเวอร์ชันล่าสุดทันทีหลังติดตั้ง
pacman -Syu --noconfirm

echo "=== Installing systemd-boot ==="
bootctl --path=/boot install

# Get root partition UUID
root_uuid=$(blkid -s UUID -o value ${DISK}2)
efi_uuid=$(blkid -s UUID -o value ${DISK}1)

echo "Root UUID: $root_uuid"
echo "EFI UUID: $efi_uuid"

# Create boot entry directory
mkdir -p /boot/loader/entries

# สร้าง boot entry ที่ใช้ wildcard สำหรับ kernel ใดๆ
# จะทำให้รองรับการเปลี่ยน kernel ได้
# เพิ่ม kernel parameters เพื่อเพิ่มความเร็วในการบูต
cat > /boot/loader/entries/arch.conf << EOF
title   Arch Linux
linux   /vmlinuz-linux-zen
initrd  /initramfs-linux-zen.img
options root=UUID=${root_uuid} rw quiet loglevel=3 nowatchdog nvme_load=YES
EOF

# Configure loader
cat > /boot/loader/loader.conf << EOF
default arch.conf
timeout 0
console-mode keep
editor no
EOF

# สร้าง pacman hook สำหรับอัพเดท boot entry อัตโนมัติเมื่อเปลี่ยน kernel
mkdir -p /etc/pacman.d/hooks

cat > /etc/pacman.d/hooks/95-systemd-boot.hook << 'HOOKEOF'
[Trigger]
Type = Package
Operation = Upgrade
Target = systemd

[Action]
Description = Updating systemd-boot
When = PostTransaction
Exec = /usr/bin/bootctl update
HOOKEOF

cat > /etc/pacman.d/hooks/90-kernel-boot-entry.hook << 'HOOKEOF'
[Trigger]
Type = Package
Operation = Install
Operation = Upgrade
Target = linux
Target = linux-lts
Target = linux-zen
Target = linux-hardened

[Action]
Description = Updating kernel boot entries
When = PostTransaction
Exec = /usr/local/bin/update-boot-entries.sh
HOOKEOF

# สร้าง script สำหรับอัพเดท boot entries
cat > /usr/local/bin/update-boot-entries.sh << 'UPDATEEOF'
#!/bin/bash
# Auto-update boot entries for all installed kernels

ROOT_UUID=$(findmnt -n -o UUID /)
ENTRIES_DIR="/boot/loader/entries"

# ลบ entries เก่าทั้งหมด
rm -f ${ENTRIES_DIR}/arch*.conf

# หา kernels ทั้งหมดที่ติดตั้ง
for kernel in /boot/vmlinuz-*; do
    [ -f "$kernel" ] || continue
    
    kernel_name=$(basename "$kernel" | sed 's/vmlinuz-//')
    initrd="/boot/initramfs-${kernel_name}.img"
    
    # ตรวจสอบว่ามี initramfs
    if [ ! -f "$initrd" ]; then
        echo "Warning: No initramfs for $kernel_name"
        continue
    fi
    
    # สร้าง entry
    entry_file="${ENTRIES_DIR}/arch-${kernel_name}.conf"
    cat > "$entry_file" << EOF
title   Arch Linux (${kernel_name})
linux   /vmlinuz-${kernel_name}
initrd  /initramfs-${kernel_name}.img
options root=UUID=${ROOT_UUID} rw quiet loglevel=3 nowatchdog nvme_load=YES
EOF
    
    echo "Created boot entry: $entry_file"
done

# ตั้งค่า default entry (ให้ใช้ zen ถ้ามี)
if [ -f "${ENTRIES_DIR}/arch-linux-zen.conf" ]; then
    sed -i 's/^default .*/default arch-linux-zen.conf/' /boot/loader/loader.conf
elif [ -f "${ENTRIES_DIR}/arch-linux.conf" ]; then
    sed -i 's/^default .*/default arch-linux.conf/' /boot/loader/loader.conf
else
    # ใช้ entry แรกที่เจอ
    first_entry=$(ls ${ENTRIES_DIR}/arch*.conf 2>/dev/null | head -n1 | xargs basename)
    if [ -n "$first_entry" ]; then
        sed -i "s/^default .*/default $first_entry/" /boot/loader/loader.conf
    fi
fi

echo "Boot entries updated successfully"
UPDATEEOF

chmod +x /usr/local/bin/update-boot-entries.sh

# รัน script ครั้งแรก
/usr/local/bin/update-boot-entries.sh

echo "=== Updating systemd-boot ==="
bootctl update

echo "=== Enabling services ==="
systemctl enable systemd-networkd
systemctl enable systemd-resolved
systemctl enable systemd-timesyncd
systemctl enable sshd

echo "=== Configuring locale ==="
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
echo "LANG=en_US.UTF-8" >> /etc/locale.conf
locale-gen

echo "=== Configuring hostname and timezone ==="
echo "$HOSTNAME" > /etc/hostname
cat << EOF > /etc/hosts
127.0.0.1   localhost
::1         localhost
127.0.1.1   ${HOSTNAME}.localdomain ${HOSTNAME}
EOF

ln -sf "/usr/share/zoneinfo/$TZ" /etc/localtime
hwclock --systohc || true

echo "=== Optimizing boot speed ==="
# ปิด service ที่ไม่จำเป็นต่อการบูต
systemctl mask systemd-networkd-wait-online.service

# ตั้งค่า systemd สำหรับการบูตเร็วขึ้น
mkdir -p /etc/systemd/system.conf.d
cat > /etc/systemd/system.conf.d/boot-optimization.conf << 'EOF'
[Manager]
# ลดเวลา timeout
DefaultTimeoutStartSec=10s
DefaultTimeoutStopSec=10s
DefaultDeviceTimeoutSec=10s

# เพิ่มความเร็วในการทำงาน
DefaultStartLimitIntervalSec=10s
DefaultStartLimitBurst=5
EOF

# ปรับแต่ง journald เพื่อลดการเขียน disk
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/boot-optimization.conf << 'EOF'
[Journal]
# ลดการเขียน log ระหว่างบูต
Storage=volatile
RuntimeMaxUse=50M
EOF

# ตั้งค่า systemd-resolved ให้เร็วขึ้น
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/boot-optimization.conf << 'EOF'
[Resolve]
# ใช้ DNS cache เพื่อความเร็ว
Cache=yes
CacheFromLocalhost=yes
DNSSEC=no
DNSOverTLS=no
MulticastDNS=no
LLMNR=no
EOF

echo "=== Creating user: $USERNAME ==="
useradd -m -G wheel -s /bin/bash "$USERNAME"
echo "${USERNAME}:${PASSWORD}" | chpasswd

echo "=== Configuring sudo ==="
sed -i 's/^# %wheel ALL=(ALL:ALL) NOPASSWD: ALL/%wheel ALL=(ALL:ALL) NOPASSWD: ALL/' /etc/sudoers
sed -i 's/^%wheel ALL=(ALL:ALL) ALL/# %wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

echo "=== Configuring SSH ==="
mkdir -p /home/${USERNAME}/.ssh
chmod 700 /home/${USERNAME}/.ssh
curl -fSsL "$AUTHORIZED_KEYS" > /home/${USERNAME}/.ssh/authorized_keys
chmod 600 /home/${USERNAME}/.ssh/authorized_keys
chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}/.ssh

sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

echo "=== Locking root account ==="
passwd -l root

echo "=== User configuration saved ==="
cat > /home/${USERNAME}/login_info.txt << EOF
Hostname: ${HOSTNAME}
Username: ${USERNAME}
Password: ${PASSWORD}
Kernel: linux-zen
System: Fully updated (pacman -Syu completed during installation)
Boot: Optimized for fastest boot time

SSH Login:
  ssh ${USERNAME}@<server-ip>
  (Uses SSH key only, password disabled for SSH)

Sudo: No password required (NOPASSWD enabled)

Password can be used for:
  - xrdp (Remote Desktop)
  - Console/TTY login
  - su command

Note: Root login is disabled for security.

Boot Optimizations Applied:
  - Bootloader timeout: 0 seconds (instant boot)
  - Kernel parameters: quiet, loglevel=3, nowatchdog
  - Initramfs compression: zstd (fastest)
  - Systemd timeouts: Reduced to 10s
  - Journal storage: volatile (RAM only during boot)
  - Network wait: Disabled (systemd-networkd-wait-online masked)
  - DNS: Local cache enabled, DNSSEC/DoT disabled for speed

Kernel Management:
  - Current kernel: linux-zen
  - To install another kernel: sudo pacman -S linux (or linux-lts, linux-hardened)
  - Boot entries are auto-updated via pacman hooks
  - To manually update: sudo /usr/local/bin/update-boot-entries.sh
  - View boot entries: bootctl list
  - Change default: sudo bootctl set-default <entry>
  - Check boot time: systemd-analyze / systemd-analyze blame

System Maintenance:
  - System is already fully updated
  - To update later: sudo pacman -Syu
  - Clean package cache: sudo pacman -Sc

No fstab - systemd handles mounting automatically.
EOF
chmod 600 /home/${USERNAME}/login_info.txt
chown ${USERNAME}:${USERNAME} /home/${USERNAME}/login_info.txt

echo "=== Building initramfs ==="
touch /etc/vconsole.conf

# ปรับแต่ง mkinitcpio เพื่อความเร็ว
cat > /etc/mkinitcpio.conf << 'EOF'
# MODULES - เพิ่มเฉพาะที่จำเป็น
MODULES=(ext4)

# BINARIES
BINARIES=()

# FILES
FILES=()

# HOOKS - ลดเหลือเฉพาะที่จำเป็น เพื่อความเร็ว
# ไม่ใช้ autodetect เพื่อความเสถียร แต่เลือก hooks น้อยที่สุด
HOOKS=(base systemd autodetect modconf kms keyboard sd-vconsole block filesystems fsck)

# COMPRESSION - ใช้ zstd เพื่อความเร็วในการบูต
COMPRESSION="zstd"
COMPRESSION_OPTIONS=(-1 -T0)
EOF

mkinitcpio -P

echo "Installation complete!"
INSTALLSCRIPT

    chmod +x /mnt/root/install.sh
    
    echo "=== Running installation in chroot ==="
    chroot /mnt /root/install.sh "$ACTION" "$USERNAME" "$PASSWORD"
    
    echo "=== Configuring network ==="
    if [ -n "$ipv6_gateway" ] && [ -n "$ipv6_address" ] && [ "$ipv6_address" != "::1" ]; then
        cat << EOF > /mnt/etc/systemd/network/20-ovh.network
[Match]
Name=en*

[Network]
DHCP=ipv4
Address=${ipv6_address}/${ipv6_prefix}
Gateway=${ipv6_gateway}
DNS=1.1.1.1
DNS=8.8.8.8
DNS=2606:4700:4700::1111
DNS=2001:4860:4860::8888
EOF
    else
        echo "IPv6 not configured, using IPv4 only"
        cat << EOF > /mnt/etc/systemd/network/20-ovh.network
[Match]
Name=en*

[Network]
DHCP=ipv4
DNS=1.1.1.1
DNS=8.8.8.8
EOF
    fi

    echo "=== Cleaning up ==="
    # ออกจาก chroot ก่อน (ถ้ามี process ค้าง)
    sync
    
    # ใช้ฟังก์ชัน safe_umount สำหรับทุก mount point
    # Umount ตามลำดับจากใน -> นอก
    safe_umount /mnt/tmp
    safe_umount /mnt/sys
    safe_umount /mnt/proc
    safe_umount /mnt/dev/pts
    safe_umount /mnt/dev
    safe_umount /mnt/boot
    safe_umount /mnt
    
    echo ""
    echo "======================================"
    echo "Installation completed successfully!"
    echo "======================================"
    echo "Hostname: $ACTION"
    echo "Username: $USERNAME"
    echo "Kernel: linux-zen"
    echo "System: Fully updated (pacman -Syu completed)"
    echo "Boot: Optimized for maximum speed"
    echo "IPv4: $ipv4_address/$ipv4_prefix (gateway: $ipv4_gateway)"
    if [ -n "$ipv6_gateway" ] && [ "$ipv6_address" != "::1" ]; then
        echo "IPv6: $ipv6_address/$ipv6_prefix (gateway: $ipv6_gateway)"
    fi
    echo ""
    echo "Install log saved to: /tmp/install.log"
    echo ""
    echo "SSH: Key-based authentication only"
    echo "Login: ssh $USERNAME@$ipv4_address"
    echo "Sudo: NOPASSWD (no password required)"
    echo "Password: Available for xrdp/console login"
    echo ""
    echo "Boot Optimizations:"
    echo "  • Bootloader timeout: 0s (instant)"
    echo "  • Kernel params: quiet, nowatchdog, optimized"
    echo "  • Initramfs: zstd compression (fastest)"
    echo "  • Systemd: Reduced timeouts (10s)"
    echo "  • Network: No wait for online"
    echo "  • Journal: Volatile storage during boot"
    echo "  • After boot, check: systemd-analyze"
    echo ""
    echo "Kernel Features:"
    echo "  • linux-zen kernel installed"
    echo "  • Auto-update boot entries on kernel changes"
    echo "  • Pacman hooks enabled for kernel management"
    echo "  • To install additional kernels:"
    echo "    sudo pacman -S linux        # Standard kernel"
    echo "    sudo pacman -S linux-lts    # Long-term support"
    echo "    sudo pacman -S linux-hardened # Hardened kernel"
    echo ""
    echo "System Maintenance:"
    echo "  • System is fully updated (no need to run pacman -Syu)"
    echo "  • All packages are at the latest version"
    echo "  • Future updates: sudo pacman -Syu"
    echo ""
    echo "No fstab - systemd handles mounting"
    echo ""
    echo "Now reboot the VPS from the OVH control panel"
    echo "======================================"
}

main
