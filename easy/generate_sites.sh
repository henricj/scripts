#!/bin/sh
fetch https://easylist.github.io/easylist/easylist.txt
awk -f easy_split.awk < easylist.txt | sort -u | ./check_servers.sh  >checkall.log 2>&1
awk -f select_pfs.awk < checkall.log | sort -u > sites.new

