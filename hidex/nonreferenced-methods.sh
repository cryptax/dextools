#!/bin/bash

SMALI_DIR='./smali'

if [ ! -d $SMALI_DIR ]
then
    echo "Please run baksmali on $1 and put smali output in $SMALI_DIR"
    exit 0
fi

if [ $# -ne 1 ]
then
    echo "Usage: ./nonreferenced-methods.sh <classes.dex file>"
    exit 0
fi

NOT_REFERENCED=`./hidex.pl --detect --input $1 | grep "never referenced" | awk '{ print $5,"->",$7; }'|sed -e 's/ //g'`

for i in $NOT_REFERENCED
do
    found=`grep -rl -m 1 "$i" $SMALI_DIR | wc -l`
    if [ $found -eq 0 ]
    then
	echo "Method $i is never used"
    fi
done

