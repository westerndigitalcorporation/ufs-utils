# UFS Tool #

## Description: ##
a) Read/Write device flags, attributes & descriptors by
using the BSG infrastructure in linux kernel (applied to 5.1 rc1)   
b) Get/Set UNIPRO attributes   
c) HMR - Host Manual Refresh functionality     
The following options may work with the SCSI BSG device   
using sg v4 structure (e.g. /dev/0:0:0:0)    
or via a SCSI Generic interface using sg v3 struct (e.g. /dev/block/sda)       
d) Error History     
e) FFU - Field Firmware Update   
f) Send Vendor commands based on SCSI WRITE/READ Buffer commands   
g) RPMB functionality     
  
The tool is aligned to the UFS 3.1 spec.   

## Build: ##
### Set CROSS\_COMPILE variable(e.g.): ###
export CROSS\_COMPILE=/XXX/aarch64-linux-gnu-

### Build: ###
"make"

### Clean: ###
 "make clean"   

## Usage ##
Copy the tool into a directory on the device (e.g.
/data/local/tmp).   
Run the tool without arguments or with -h/--help
    options in order to list the supported features:   
E.g. Run:  
./ufs-utils --help  
Output:
    ufs-utils help|--help|-h Show the help.

        ufs-utils -v
                Show the version.

        ufs-utils <desc | attr | fl | err_hist | uic | ffu | vendor | rpmb | hmr | arpmb> --help|-h
                Show detailed help for a command

    Run the tool's help for the ufs configuration features in order to
    get full information related to the feature, all options and the
    examples. E.g.: getting help for ufs flags Run: ./ufs-utils fl --help
    Output: Flags command usage:

        ufs-utils fl [-t] <flag idn> [-a|-r|-o|-e] [-p] <device_path> 

        -t       Flags type idn
                 Available flags and its access, based on UFS ver 3.0 :
                         0  : Reserved
                         1  : fDeviceInit                | Read | SetOnly
                         2  : fPermanentWPEn             | Read | WriteOnce
                         3  : fPowerOnWPEn               | Read | ResetOnPower
                         4  : fBackgroundOpsEn           | Read | Volatile
                         5  : fDeviceLifeSpanModeEn      | Read | Volatile
                         6  : fPurgeEnable               | WriteOnly | Volatile
                         7  : fRefreshEnable             | WriteOnly | Volatile
                         8  : fPhyResourceRemoval        | Read | Persistent
                         9  : fBusyRTC                   | ReadOnly
                         10 : Reserved
                         11 : fPermanentlyDisableFw      | Read | WriteOnce

        -a       read and print all readable flags for the device

        -r       read operation (default), for readable flag(s)

        -e       set flag operation

        -c       clear/reset flag operation

        -o       toggle flag operation

        -p       path to ufs bsg device

        Example - Read the bkops operation flag
                ufs-utils fl -t 4 -p /dev/ufs-bsg

## Authors ##
signed-off-by:Arthur Simchaev (arthur.simchaev@wdc.com)
signed-off-by:Avri Altman (avri.altman@wdc.com)

## License ##
This project is licensed under the GPL-2.0-only  
See [COPYING](COPYING) to see the full text.
