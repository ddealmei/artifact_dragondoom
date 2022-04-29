# Dragondoom: Proof of Concept attack on Dragonfly

The PAKE Dragonfly is used as SAE in WPA3 authentication. 
A critical point during the authentication is when the password needs to be derived into an elliptic curve point. 

This is currently implemented through the *hunting-and-pecking* approach (though a new method is being standardized). Briefly put, this approach basically tries to convert the password with different counter values until it succeeds ([common/sae.c:276](https://w1.fi/cgit/hostap/tree/src/common/sae.c?h=hostap_2_9&id=ca8c2bd28ad53f431d6ee60ef754e98cfdb4c17b#n276)). It then continues with dummy values to avoid side-channel leakage. 

Once the loop is done, the actual point is instantiated using the `crypto_ec_point_solve_y_coord` ([common/sae.c:410](https://w1.fi/cgit/hostap/tree/src/common/sae.c?h=hostap_2_9&id=ca8c2bd28ad53f431d6ee60ef754e98cfdb4c17b#n410)) with `x` and `seed_parity`. During this operation, we find that an attacker can learn whether  `y mod 2 == seed_parity`.
This information is valuable, since it is strongly related to the used password, which allows the attacker to perform an offline dictionary attack.

We implemented a PoC of the entire attack workflow on release version of wpa_supplicant v2.9, compiled for use with OpenSSL v1.1.1l, but using WolfSSL would result in the same leakage.

## Repository layout

* PoC_material: contains all the materials to be used to build the docker
* shared_folder: is shared between the docker and the host, making it easier to transmit files. Namely, it contains a sample of the data we were able to extract during our experiment.

## Run the PoC

We provide a docker to avoid any compatibility issue. However, it is worth noting that the nature of our attack (cache side-channels) makes the exact outcome of the spy process dependent of the executing CPU, which might lead to less reliable results. This reliability issue can be solved with more automated approach concerning the cache attack. However, we decided not to focus on that for this PoC. Instead, we included a sample of our results in shared_folder/results.

To test this attack, we assume you have access to an access point supporting WPA3 (we used a smartphone in our test). You need to either set the access point SSID to "TestAP", or change the `ENV AP_SSID="TestAP"` to the right value in the Dockerfile. In the attack scenario, this would be a rogue access point, advertizing an existing SSID with stronger power for instance.

### Setup the environment 

First, build the docker:
```bash
sudo docker build --rm -t poc_dragonfly .
```

Since our docker will use the wifi interface of our host, we need to disable our running wifi daemon on the host before running the attack (otherwise the wifi daemon will not start in the docker). Run the following on your host:
```bash
sudo pkill wpa_supplicant
```

The following command line uses `iw` to find the available wifi interface name. You may need to install it, or manually set `NET_INTERFACE`. 
You can then run the docker:
```bash
sudo docker run --mount type=bind,source="$(pwd)"/shared_folder,target=/PoC/shared_folder --net='host' --privileged -e NET_INTERFACE=$(iw dev | awk '$1=="Interface"{print $2}') -it poc_dragonfly
``` 

### Running experiments


Inside the docker, you may run the following command to reproduce our results. If the password is not provided, it will be chosen randomly from a dictionary (see variable DICTIONARY in the script). You may want to set `DICTIONARY` to `$DATA_DIR/100_passwords.txt` for a faster run.:
```bash
./attack_simulation_hostapd.sh [password]
```

This last command will actually perform the entire attack on a small dictionary (to avoid . It will run the following steps:
```
1. Get the MAC address of the Access Point.
2. Take a random password from a (small) dictionary, or the input,, and set wpa_supplicant configuration to connect to the AP using the chosen password.
3. Acquire various execution traces:
    a. Change the client MAC address to be able to repeat measurement and get new information. In a practical attack, the rogue AP would change its MAC, but it was easier to automate, and the end result is the same.
    b. Start the spy process.
    c. Start wpa_supplicant, triggering the authentication process.
4. Parse all the measurements, and use the information to perform an offline dictionary attack.
```

As mentioned above, the first step may be an issue on different CPU, so you may need to run the parsing and reduction on the data we provide to get reliable results.
To do so, simply run the following in the container. You may change the dictionary to test on more realistic cases (we didn't want to )
```bash
./shared_folder/dict_attack.sh $DATA_DIR/rockyou.txt /PoC/shared_folder/results/dragonfly123
``` 

You may also see the validity of data collected for a specific password by comparing it to the ground truth with the script `./shared_folder/eval_results.sh`. For instance, you may run the following to assess all the data we collected:

```bash
tar xzf ./shared_folder/results.tar.gz -C ./shared_folder/
for res in ./shared_folder/results/*
do 
    password=$(basename $res)
    echo -e "\n$password"
    ./shared_folder/eval_results.sh "$password"
done
```

## Restoring your WiFi

Since we needed to kill any running wpa_supplicant, you can restore yours with the following:
```sh
sudo /sbin/wpa_supplicant -B -u -s -O /run/wpa_supplicant
```
