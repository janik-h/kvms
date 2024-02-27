#!/bin/bash -e

export PATH=$PATH:/usr/sbin
cd "$(dirname "$0")"
modprobe nbd max_part=8

UBUNTU_STABLE=http://cdimage.debian.org/mirror/cdimage.ubuntu.com/ubuntu-base/releases/20.04/release/ubuntu-base-20.04.1-base-arm64.tar.gz
QEMU_USER=`which qemu-aarch64-static`
CPUS=`nproc`

USERNAME=$1
CURDIR=$PWD
BASE_DIR=$PWD
UBUNTU_BASE=$UBUNTU_STABLE
PKGLIST=`cat package.list.20 |grep -v "\-dev"`
EXTRA_PKGLIST=`cat extra_package.list`
OUTFILE=ubuntugh.qcow2
OUTDIR=$BASE_DIR/guest/images
SIZE=6G

do_unmount()
{
	if [[ $(findmnt -M "$1") ]]; then
		sudo umount $1
		if [ $? -ne 0 ]; then
			echo "ERROR: failed to umount $1"
			exit 1
		fi
	fi
}

do_cleanup()
{
	cd $CURDIR
	do_unmount tmp/proc || true
	do_unmount tmp/dev || true
	do_unmount tmp || true
	qemu-nbd --disconnect /dev/nbd7 || true
	sync || true
	if [ -f $OUTDIR/$OUTFILE ]; then
		chown $USERNAME.$USERNAME $OUTDIR/$OUTFILE
	fi

	rmmod nbd
	rm -rf tmp linux `basename $UBUNTU_BASE`
}

usage() {
	echo "$0 -o <output directory> -s <image size> | -u"
}

trap do_cleanup SIGHUP SIGINT SIGTERM EXIT

while getopts "h?u:o:s:" opt; do
	case "$opt" in
	h|\?)	usage
		exit 0
		;;
	u)	UBUNTU_BASE=$UBUNTU_UNSTABLE
		;;
	o)	OUTDIR=$OPTARG
		;;
	s)	SIZE=$OPTARG
		;;
  esac
done

echo "Creating image.."
qemu-img create -f qcow2 $OUTFILE $SIZE
qemu-nbd --connect=/dev/nbd7 $OUTFILE
# parted -a optimal /dev/nbd7 mklabel gpt mkpart primary ext4 0% 100%
sync

echo "Formatting & downloading.."
mkfs.ext4 /dev/nbd7
wget -c $UBUNTU_BASE
sync

echo "Extracting ubuntu.."
mkdir -p tmp
mount /dev/nbd7 tmp
tar xf `basename $UBUNTU_BASE` -C tmp
cp $QEMU_USER tmp/usr/bin

echo "Installing packages.."
mount --bind /dev tmp/dev
mount -t proc none tmp/proc
echo "nameserver 8.8.8.8" > tmp/etc/resolv.conf
export DEBIAN_FRONTEND=noninteractive
sudo -E chroot tmp apt-get update
sudo -E chroot tmp apt-get -y install $PKGLIST
sudo -E chroot tmp update-alternatives --set iptables /usr/sbin/iptables-legacy
sudo -E chroot tmp adduser --disabled-password --gecos "" ubuntu
sudo -E chroot tmp passwd -d ubuntu
sudo -E chroot tmp usermod -aG sudo ubuntu

cat >>  tmp/etc/network/interfaces << EOF
auto lo
iface lo inet loopback

auto enp0s6
iface enp0s6 inet static
address 192.168.8.3
gateway 192.168.8.1
EOF

if [ ! -d $OUTDIR ]; then
	echo "Creating output dir.."
	mkdir -p $OUTDIR
	chown $USERNAME.$USERNAME $OUTDIR
fi

mv $OUTFILE $OUTDIR
echo "Output saved at $OUTDIR"
sync
