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
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
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

function main() {
    if [[ -z "$ACTION" ]]; then
        echo "Usage: $0 <hostname>"
        exit 1
    fi
    
    echo "=== Starting Arch Linux installation ==="
    echo "Target disk: $DISK"
    echo "Hostname: $ACTION"
    
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

    echo "=== Setting up bootstrap environment ==="
    mkdir -p /bootstrap
    mount -t tmpfs tmpfs /bootstrap
    mount "${DISK}2" /bootstrap
    cd /bootstrap
    tar xf /tmp/archlinux.tar.zst --numeric-owner --strip-components=1 2>&1 | grep -v "Ignoring unknown extended header keyword" || true
    
    mount "${DISK}2" /bootstrap/mnt
    mkdir -p /bootstrap/mnt/boot/efi
    mount "${DISK}1" /bootstrap/mnt/boot/efi

    echo "=== Configuring pacman ==="
    sed -i -e 's@#Server = https://mirror.rackspace.com@Server = https://mirror.rackspace.com@' /bootstrap/etc/pacman.d/mirrorlist
    sed -i -e 's/#ParallelDownloads/ParallelDownloads/' /bootstrap/etc/pacman.conf
    cp "$SCRIPT_PATH" /bootstrap/root/bootstrap.sh
    chmod +x /bootstrap/root/bootstrap.sh
    
    echo "=== Running pacstrap ==="
    cd /
    /bootstrap/bin/arch-chroot /bootstrap /root/bootstrap.sh 'do_pacstrap'
    
    echo "=== Finalizing installation ==="
    /bootstrap/bin/arch-chroot /bootstrap/mnt/ /root/bootstrap.sh 'finalize' "$ACTION"

    echo "=== Configuring network ==="
    if [ -n "$ipv6_gateway" ] && [ -n "$ipv6_address" ] && [ "$ipv6_address" != "::1" ]; then
        cat << EOF > /bootstrap/mnt/etc/systemd/network/20-ovh.network
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
        cat << EOF > /bootstrap/mnt/etc/systemd/network/20-ovh.network
[Match]
Name=en*

[Network]
DHCP=ipv4
DNS=1.1.1.1
DNS=8.8.8.8
EOF
    fi

    echo "=== Cleaning up ==="
    rm /bootstrap/root/bootstrap.sh
    sync
    umount /bootstrap/mnt/boot/efi
    umount /bootstrap/mnt
    umount /bootstrap
    
    echo ""
    echo "======================================"
    echo "Installation completed successfully!"
    echo "======================================"
    echo "Hostname: $ACTION"
    echo "IPv4: $ipv4_address/$ipv4_prefix (gateway: $ipv4_gateway)"
    if [ -n "$ipv6_gateway" ] && [ "$ipv6_address" != "::1" ]; then
        echo "IPv6: $ipv6_address/$ipv6_prefix (gateway: $ipv6_gateway)"
    fi
    echo ""
    echo "Install log saved to: /tmp/install.log"
    echo ""
    echo "Now reboot the VPS from the OVH control panel"
    echo "After reboot, you can login via SSH as root"
    echo "======================================"
}

function do_pacstrap() {
    echo "=== Initializing pacman keyring ==="
    pacman-key --init
    pacman-key --populate archlinux
    
    echo "=== Installing base system ==="
    # ลบ grub และ efibootmgr ออก
    pacstrap /mnt base linux linux-firmware openssh
    
    echo "=== Generating fstab ==="
    genfstab -U /mnt >> /mnt/etc/fstab
}

function finalize() {
    local hostname="$1"
    
    echo "=== Installing systemd-boot ==="
    bootctl install
    
    echo "=== Configuring systemd-boot ==="
    # สร้าง loader configuration
    cat << EOF > /boot/loader/loader.conf
default arch.conf
timeout 2
console-mode max
editor no
EOF
    
    # หา root partition UUID
    local root_uuid=$(blkid -s UUID -o value ${DISK}2)
    
    # สร้าง boot entry
    cat << EOF > /boot/loader/entries/arch.conf
title   Arch Linux
linux   /vmlinuz-linux
initrd  /initramfs-linux.img
options root=UUID=${root_uuid} rw
EOF
    
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
    echo "$hostname" > /etc/hostname
    cat << EOF > /etc/hosts
127.0.0.1   localhost
::1         localhost
127.0.1.1   ${hostname}.localdomain ${hostname}
EOF
    
    ln -sf "/usr/share/zoneinfo/$TZ" /etc/localtime
    hwclock --systohc || true

    echo "=== Configuring SSH ==="
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    curl -fSsL "$AUTHORIZED_KEYS" > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    
    sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    echo "=== Setting root password ==="
    local root_pass=$(openssl rand -base64 32)
    echo "root:${root_pass}" | chpasswd
    echo "Root password: ${root_pass}" > /root/initial_password.txt
    chmod 600 /root/initial_password.txt
    echo "Random root password has been set and saved to /root/initial_password.txt"

    echo "=== Building initramfs ==="
    touch /etc/vconsole.conf
    mkinitcpio -P
    
    echo "Finalization complete!"
}

case "$ACTION" in
    do_pacstrap)
        shift
        do_pacstrap "$@"
        ;;
    finalize)
        shift
        finalize "$@"
        ;;
    *)
        main
        ;;
esac
