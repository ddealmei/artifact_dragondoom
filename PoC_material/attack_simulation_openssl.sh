#!/bin/bash

nb_tests=20 #$(wc -l ./test_calibration/point_y_even.txt | awk '{print $1}')
nb_measurements=10
mkdir -p "$RES_DIR/attack_simulation"
for j in `seq 1 $nb_measurements`;
do
    for i in `seq 1 $nb_tests`;
    do
        printf "\rMeasurement %2d/$nb_measurements - x_%2d/$nb_tests" $j $i
        x=$(sed "${i}q;d" $DATA_DIR/point_y_even.txt)
        run_spy.sh -f -o $RES_DIR/attack_simulation/same_parity_$i-$j.log &
        spy_pid=$!
        sleep 0.5
        /PoC/poc_openssl $x 0
        sleep 0.5
        kill $spy_pid
        pkill FR-trace
        
        # Do some computation in between 
        sha512sum $RES_DIR/attack_simulation/* 2>&1 >/dev/null

        run_spy.sh -f -o $RES_DIR/attack_simulation/diff_parity_$i-$j.log &
        spy_pid=$!
        sleep 0.5
        /PoC/poc_openssl $x 1
        sleep 0.5
        kill $spy_pid
        pkill FR-trace
    done
done
