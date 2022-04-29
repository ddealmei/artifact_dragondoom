#!/bin/bash
conf_threshold=0.50

for file in $(find shared_folder/results/ -name "*$1-*.log" | awk -F '-' '{printf "%s\n", $1}' |sort -u);
do
    # logfile=$(basename $file)
    # filebase=$(awk -F'-' '{print $1}' <<< $logfile)
    filebase=$(basename $file)
    ground_truth=$(./poc_full_session $filebase)
    gt_0=$(awk '{print $2}' <<< $ground_truth)
    gt_1=$(awk '{print $3}' <<< $ground_truth)
    if [[ $gt_0 == $gt_1 ]]
    then
        gt=1
    else
        gt=0
    fi
    obs=$(echo -n "$(./parser.py $file*.log 2>/dev/null)" | awk -F ':' '{ $1=""; $2=""; print}')
    conf=$(echo $obs | awk '{print $3'})
    res=$(echo $obs | awk '{print $1'})
    if [[ $res != $gt ]]; then
        if (( $(echo "$conf < $conf_threshold" |bc -l) )); then
            echo -e "\033[0;31m$(basename $file) $gt | $obs\033[0m"
        else
            echo -e "\033[0;31m$(tput bold)$(basename $file) $gt | $obs$(tput sgr0)\033[0m"
        fi
    else
        if (( $(echo "$conf < $conf_threshold" |bc -l) )); then
            echo -e "\033[0;33m$(basename $file) $gt | $obs\033[0m"
        else
            echo -e "\033[0;32m$(basename $file) $gt | $obs\033[0m"
        fi
    fi
done
