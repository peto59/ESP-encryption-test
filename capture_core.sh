#!/bin/bash
idf.py monitor | tee monitor.log
sed -n '/CORE DUMP START/,/CORE DUMP END/p' monitor.log > core_dump_raw.txt
sed '1d;$d' core_dump_raw.txt > core_dump.txt
idf.py coredump-debug -c ./core_dump.txt
#p *(encryption_t *)$a3
