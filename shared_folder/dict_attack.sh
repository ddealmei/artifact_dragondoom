#!/bin/bash

# We may need to extract the archive the first time
[ -f $DATA_DIR/rockyou.txt ] || tar xzf $DATA_DIR/rockyou.txt.tar.gz -C $DATA_DIR

dictionary=$1
log_dir=$2

echo "Parsing traces"
traces=""
file_list=$(ls $log_dir/* | awk -F '-' '{printf "%s\n", $1}' | sort -u)
for f in $file_list; 
do 
	t=$(./parser.py $f*.log 2>/dev/null)
	conf=$(echo $t | awk -F':' '{print $5'})
	if (( $(echo "$conf > 0.50" |bc -l) ))
	then 
		traces="$traces $(echo -n $t | cut -d':' -f1,2,3)"
	fi
done

echo -e "Performing dictionary reduction"
./dictionary_reducer $dictionary $traces