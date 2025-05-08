#!/bin/sh

set -e
ARTIFACT=""
kernel_src_dir=""
kernel_version=""
install_image=false
sign_image=false

help()
{
# Display help
echo "Usage"
echo "Script to build and install vtl0 kernel, vtl1 secure loader and vtl1 secure kernel"
echo "Syntax: ./lvbs-build.sh [--vtl0 | -i/--install |-h/--help]"
echo ""
echo "--vtl0/--vtl1/--loader    Artifact to build and/or install"
echo ""
echo "-i | --install            Install the artifact"
echo "-h | --help               Display the help menu"
}

while (( "$#" )); do
        case "$1" in
	--vtl0)
	   ARTIFACT="vtl0"
	   shift
           ;;
	--loader)
	   ARTIFACT="loader"
	   shift
	   ;;
	--vtl1)
	   ARTIFACT="vtl1"
	   shift
	   ;;
	-i | --install)
	   install_image=true
	   shift
	   ;;
	-s | --sign)
	   sign_image=true
	   kernel_src_dir=$2
	   if [ -z "$kernel_src_dir" ];
           then
                 echo "Please specify the vtl0 kernel source directory to find signing script and certificates"
                 help
                 exit 1;
           fi
	   shift 2
	   ;;
	-k | --kernel_ver)
	   kernel_version=$2
	   shift 2
	   ;;
        -h|--help)
           help
           exit
           ;;
         *)
          echo "Error: Unsupported argument"
	  help
          exit 1
          ;;
        esac
done

if [ -z "$ARTIFACT" ]
then
        echo "Please specify the build and install artifact"
        help
        exit 0;
fi

if [ -z "$kernel_version" ];
then
	kernel_version=$( uname -r | awk -F '[.-]' '{print $1"."$2"."$3"."$4}' )
fi
kernel_version=$kernel_version"-lvbs+"
echo $kernel_version

if [ "$ARTIFACT" == "loader" ]; then
	echo "Building and installing secure loader"
	make clean
	make
	if [ "$install_image" = true ]; then
	   sudo rm -f /usr/lib/firmware/skloader.bin
	   sudo cp skloader.bin /usr/lib/firmware
	   if [ "$sign_image" = true ];
           then
                echo "Signing the secure loader"
		sudo rm -f /usr/lib/firmware/skloader.bin.p7s
                sudo $kernel_src_dir/scripts/sign-file -dp sha256 $kernel_src_dir/certs/signing_key.pem $kernel_src_dir/certs/signing_key.x509 /usr/lib/firmware/skloader.bin
           fi
           sudo dracut -H -f /boot/initramfs-$kernel_version".img" $kernel_version
	fi
elif [ "$ARTIFACT" == "vtl0" ]; then
	echo "Building and installing VTL0 kernel"
	./scripts/kconfig/merge_config.sh -m .config Microsoft/lvbs.config
	make olddefconfig
        make -j$(nproc --ignore 1)
	if [ "$install_image" = true ]; then
            sudo make -j$(nproc --ignore 1) modules_install
	    sudo cp arch/x86/boot/bzImage /boot/vmlinuz-$kernel_version
	    if [ ! -f /boot/initramfs-$kernel_version ]; then
               sudo dracut -H -f /boot/initramfs-$kernel_version".img" $kernel_version
	    fi
	fi
elif [ "$ARTIFACT" == "vtl1" ]; then
        cp Microsoft/mshv_sk_config .config
	make olddefconfig
        make -j23 vmlinux
	if [ "$install_image" = true ]; then
	   objcopy -O binary -R .note -R .comment -S vmlinux vmlinux.bin
           sudo rm -f /usr/lib/firmware/vmlinux.bin
           sudo cp vmlinux.bin /usr/lib/firmware
	   if [ "$sign_image" = true ];
           then
                echo "Signing the secure kernel"
		sudo rm -f /usr/lib/firmware/vmlinux.bin.p7s
                sudo $kernel_src_dir/scripts/sign-file -dp sha256 $kernel_src_dir/certs/signing_key.pem $kernel_src_dir/certs/signing_key.x509 /usr/lib/firmware/vmlinux.bin
           fi
           sudo dracut -H -f /boot/initramfs-$kernel_version".img" $kernel_version
        fi
fi
