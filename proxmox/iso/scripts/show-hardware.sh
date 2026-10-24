#!/bin/sh
# Read-only Linux hardware inventory. Run on the intended target before erasing anything.
set -eu
printf '\nMachine UUID (may ask for the Linux administrator password):\n'
sudo cat /sys/class/dmi/id/product_uuid
printf '\nWhole disks: names, exact byte capacities, models and serials:\n'
lsblk -d -b -o NAME,SIZE,MODEL,SERIAL,RO,RM
printf '\nStable disk aliases (ignore aliases ending in -part<number>):\n'
ls -l /dev/disk/by-id/
printf '\nNetwork interfaces and MAC addresses:\n'
ip -br link
