# SSID Sybil

Advertise WiFi simulating many different access points

## Setup

Use airmon-ng to check and clear all processes using the wifi interface:

```
$ airmon-ng check

[root@merov2 ~]# airmon-ng check

Found 5 processes that could cause trouble.
If airodump-ng, aireplay-ng or airtun-ng stops working after
a short period of time, you may want to run 'airmon-ng check kill'

  PID Name
 1067 avahi-daemon
 1070 avahi-daemon
 1368 NetworkManager
18562 wpa_supplicant
18957 dhclient

$ systemctl stop NetworkManager
$ killall -9 wpa_supplicant dhclient
```

Start monitoring the interface:

```
$ airmon-ng start wlp1s0
[root@merov2 ~]# airmon-ng start wlp1s0

PHY     Interface       Driver          Chipset

phy2    wlp1s0          iwlwifi         Intel Corporation Centrino Advanced-N 6235 (rev 24)

                (mac80211 monitor mode vif enabled for [phy2]wlp1s0 on [phy2]wlp1s0mon)
                (mac80211 station mode vif disabled for [phy2]wlp1s0)

```

Place `wlp1s0mon` inside the `ssid-sybil.py` script and install scapy:


```
sudo pip3 install scapy
```


## Run

```
sudo python3 ssid-sybil.py
```
