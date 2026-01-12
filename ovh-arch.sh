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
SCRIPT_PATH="${BASH_SOURCE[0]}"
ipv4_address=""
ipv4_prefix=""
ipv4_gateway=""
ipv6_address=""
ipv6_prefix="128"
ipv6_gateway=""

get_network_info() {
    # Get the default route interface. This is typically the primary interface.
    local iface=$(ip -4 route | grep default | sed -e "s/^.*dev \([^ ]*\) .*$/\1/")
    if [ -z "$iface" ]; then
        echo "Could not determine default IPv4 interface." >&2
        exit 1
    fi

    # Get the IP address and prefix for that interface
    local ip_info=$(ip -4 addr show dev "$iface" | grep "inet " | awk '{print $2}')
    if [ -z "$ip_info" ]; then
        echo "Could not determine IPv4 address for interface $iface." >&2
        exit 1
    fi
    ipv4_address=$(echo "$ip_info" | cut -d'/' -f1)
    ipv4_prefix=$(echo "$ip_info" | cut -d'/' -f2)

    # Get the gateway from the default route
    ipv4_gateway=$(ip -4 route | grep default | awk '{print $3}')
    if [ -z "$ipv4_gateway" ]; then
        echo "Could not determine default IPv4 gateway." >&2
        exit 1
    fi
    echo "IPv4 Address: $ipv4_address"
    echo "IPv4 Prefix: $ipv4_prefix"
    echo "IPv4 Gateway: $ipv4_gateway"

    # OVHCloud has very broken IPv6 networking. It doesnt have DHCP for IPv6
    # and it doesnt support neighbor discovery protocol, so you have to set the
    # prefix to 128 so that no nodes are treated as neighbors.
    ipv6_address=$(ip -6 route | head -n1 | cut -f1 -d" ")
    # read the gateway from the cloud-init file as the rescue env doesnt have IPv6
    # routing enabled.
    local ipv6_gateway_info=$(grep gw /etc/network/interfaces.d/50-cloud-init 2>/dev/null | head -n1 | tr -s ' ' | cut -d' ' -f7 || echo "")
    if [ -z "$ipv6_gateway_info" ]; then
        echo "Warning: Could not determine IPv6 gateway, IPv6 may not work after reboot"
        ipv6_gateway=""
    else
        ipv6_gateway=$(echo "$ipv6_gateway_info" | cut -d'/' -f1)
        echo "IPv6 Address: $ipv6_address"
        echo "IPv6 Prefix: $ipv6_prefix"
        echo "IPv6 Gateway: $ipv6_gateway"
    fi
}

function main() {
    if [[ -z "$ACTION" ]]; then
        echo "Usage: $0 <hostname>"
        exit 1
    fi
    
    echo "=== Starting Arch Linux installation ==="
    echo "Target disk: $DISK"
    echo "Hostname: $ACTION"
    
    # Check if disk exists
    if [ ! -b "$DISK" ]; then
        echo "Error: Disk $DISK does not exist" >&2
        exit 1
    fi
    
    # Warn if disk is mounted
    if mount | grep -q "$DISK"; then
        echo "Warning: $DISK has mounted partitions. Unmounting..."
        umount ${DISK}* 2>/dev/null || true
    fi
    
    get_network_info
    cd /tmp
    
    echo "=== Downloading Arch Linux bootstrap ==="
    curl -fSsL https://mirror.rackspace.com/archlinux/iso/latest/archlinux-bootstrap-x86_64.tar.zst > /tmp/archlinux.tar.zst
    
    # Verify download
    if [ ! -s /tmp/archlinux.tar.zst ]; then
        echo "Error: Failed to download Arch Linux bootstrap" >&2
        exit 1
    fi

    echo "=== Partitioning disk ==="
    sgdisk --zap-all "$DISK"
    sgdisk -n 1:2048:+512M -c 1:"EFI System Partition" -t 1:EF00 "$DISK"
    sgdisk -n 2:0:0 --typecode=2:8300 --change-name=2:"Linux Root" "$DISK"
    
    echo "=== Formatting partitions ==="
    mkfs.fat -F32 "${DISK}1"
    mkfs.ext4 -F "${DISK}2"
    sgdisk -p "$DISK"

    echo "=== Setting up bootstrap environment ==="
    mkdir -p /bootstrap
    mount -t tmpfs tmpfs /bootstrap
    mount "${DISK}2" /bootstrap
    cd /bootstrap
    tar xf /tmp/archlinux.tar.zst --numeric-owner --strip-components=1
    
    # Mount EFI partition
    mkdir -p /bootstrap/mnt/boot/efi
    mount "${DISK}2" /bootstrap/mnt
    mount "${DISK}1" /bootstrap/mnt/boot/efi

    echo "=== Configuring pacman ==="
    sed -i -e 's@#Server = https://mirror.rackspace.com@Server = https://mirror.rackspace.com@' /bootstrap/etc/pacman.d/mirrorlist
    sed -i -e 's/#ParallelDownloads/ParallelDownloads/' /bootstrap/etc/pacman.conf
    cp "$SCRIPT_PATH" /bootstrap/root/bootstrap.sh
    
    echo "=== Running pacstrap ==="
    cd /
    /bootstrap/bin/arch-chroot /bootstrap /root/bootstrap.sh 'do_pacstrap'
    
    echo "=== Finalizing installation ==="
    /bootstrap/bin/arch-chroot /bootstrap/mnt/ /root/bootstrap.sh 'finalize' "$ACTION"

    echo "=== Configuring network ==="
    # Network configuration - FIXED: Write to /mnt not /bootstrap
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
    if [ -n "$ipv6_gateway" ]; then
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
    pacstrap /mnt base linux-lts linux-firmware openssh grub efibootmgr
    
    echo "=== Generating fstab ==="
    genfstab -U /mnt >> /mnt/etc/fstab
}

function finalize() {
    local hostname="$1"
    
    echo "=== Configuring GRUB ==="
    sed -i -e 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=2/' /etc/default/grub
    sed -i -e 's/GRUB_CMDLINE_LINUX_DEFAULT.*/GRUB_CMDLINE_LINUX_DEFAULT=""/' /etc/default/grub
    
    # Install GRUB for UEFI
    grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=GRUB
    grub-mkconfig -o /boot/grub/grub.cfg
    
    echo "=== Installing additional packages ==="
    pacman --noconfirm -S vim kitty-terminfo

    echo "=== Enabling services ==="
    # Network
    systemctl enable systemd-networkd
    systemctl enable systemd-resolved
    systemctl enable systemd-timesyncd
    systemctl enable sshd

    echo "=== Updating system ==="
    pacman -Syu --noconfirm

    echo "=== Configuring locale ==="
    # Locale
    echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
    echo "LANG=en_US.UTF-8" >> /etc/locale.conf
    locale-gen

    echo "=== Setting up pacman mirrors ==="
    # Pacman mirrors
    pacman --noconfirm -S rsync reflector
    reflector --latest 20 --sort rate --save /etc/pacman.d/mirrorlist

    echo "=== Configuring hostname and timezone ==="
    # Hostname and timezone
    echo "$hostname" > /etc/hostname
    cat << EOF > /etc/hosts
127.0.0.1   localhost
::1         localhost
127.0.1.1   ${hostname}.localdomain ${hostname}
EOF
    
    ln -sf "/usr/share/zoneinfo/$TZ" /etc/localtime
    hwclock --systohc
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

    echo "=== Configuring SSH ==="
    # SSH configuration
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    curl -fSsL "$AUTHORIZED_KEYS" > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    
    # Harden SSH
    sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    echo "=== Setting root password ==="
    # Set a random root password as backup
    local root_pass=$(openssl rand -base64 32)
    echo "root:${root_pass}" | chpasswd
    echo "Root password: ${root_pass}" > /root/initial_password.txt
    chmod 600 /root/initial_password.txt
    echo "Random root password has been set and saved to /root/initial_password.txt"

    echo "=== Building initramfs ==="
    # initramfs
    touch /etc/vconsole.conf
    mkinitcpio -P
    
    echo "=== Cleaning up ==="
    pacman -Sc --noconfirm
    
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