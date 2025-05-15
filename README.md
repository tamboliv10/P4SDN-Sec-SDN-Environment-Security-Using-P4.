#P4SDN-Sec-SDN-Environment-Security-Using-P4.
SDN P4 INT deployed in Mininet and security analysis
This is an SDN implementation of P4 INT-MD for bmv2 in mininet.
SDN with P4 brings a new set of possibilities as the way the packets are processed is not defined by the vendor, but rather by the P4 program. Using this language, developers can define data plane behavior, specifying how switches shall process the packets. P4 lets developers define which headers a switch shall parse, how tables match on each header, and which actions the switch shall perform on each header. This new programmability extends the capabilities of the data plane into security features, such as stateful packet inspection and filtering, thus relieving the control plane. This offloading of security is enhanced by the ability to run at line speed as P4 runs on the programmed devices.
As a away to mimic a standard topology in a data center, we have chosen the leaf-and-spine architecture as described in the figure.
In this scenario,the INT flow can be described in the following steps:
1. Source data: one host, e.g. client h1 or h3, sends some data to a server, h2, through a P4 network.
2. INT source: if the data sent from the clients matches the pre-programmed watchlist, then the switch, s1 or s5, adds the INT header and payload to this packet.
3. INT transit. The transit switches, s2 or s4, add their INT info to the same packet.
4. INT sink. The sink switch, s3, also adds its INT info to the same packet, but then strips all info and sends the original data to the server, h2. The INT information, of the 3 servers, is encapsulated in a UDP packet towards the INT collector.

This scenario can thus be split in the following parts:
1. simulate an INT platform;
2. demonstrate the collection of INT statistics;
3. rogue host attacks;
4. detection and protection against a rogue host.

This network is simulated in mininet. Search here for more information in the [Mininet waltkthrough]
## SIMULATE AN INT PLATFORM
This platform must create INT statistics and send those to the collector. In this scenario, if the data sent by h1 matches the watch list, then there will be some INT statistics generated and sent to h4.
As part of the scenario, the h2 server is simulating 3 services: PostgreSQL, HTTPS and HTTP. So, the switches s1 and s5 are pre-configured as INT source and also pre-configured the match list for source and destination IPs and l4 ports: 5432 for PostgreSQL, 443 for HTTPS and 80 for HTTP.
### Pre-requisites
Tested in a VMWare virtualized Ubuntu 20.04LTS with 35GB of storage, 8GB of RAM and 4vCPUs. Probably any Debian system should support.
```
sudo apt install git bridge-utils curl
```
#### Install Mininet
```
git clone https://github.com/mininet/mininet
sudo PYTHON=python3 mininet/util/install.sh -n
```
#### Install P4
For Ubuntu 20.04 and Ubuntu 21.04 it can be installed as follows:
```
. /etc/os-release
  echo "deb http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${VERSION_ID}/ /" | sudo tee /etc/apt/sources.list.d/home:p4lang.list
  curl -L "http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${VERSION_ID}/Release.key" | sudo apt-key add -
  sudo apt-get update
  sudo apt install p4lang-p4c
```

#### Install other dependencies
```
sudo pip3 install psutil networkx
```
### Create the network
1. clone this repository to your machine or VM
2. change directory to the new P4INT_Mininet folder
3. type ```sudo make run```

### Packet source
INT packets are only generated if a specific packet matches the watchlist. So, we used the scapy library within a python script to craft the packets. This is a simple script that takes as input parameters the destination IP, the l4 protocol UDP/TCP, the destination port number, an optional message and the number of packets sent. Additionally, we included a command to simulate recurrent accesses to the server, e.g., every 5 seconds access to HTTPS, from the h1 and h3 hosts’ CLI:
```
watch -n 5 python3 send.py --ip 10.0.3.2 -l4 udp --port 443 --m INTH1 --c 1
```
You can find ready-made scripts for h1 and h3 in [h1 to h2](send/h1.sh) and [h3 to 24](send/h3.sh)

You may search for information about the scapy in [The Art of Packet Crafting with Scapy](https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sending_recieving/index.html)
Install Influxdb
1. Install influxdb with https://docs.influxdata.com/influxdb/v1.8/introduction/install/
```
wget -q https://repos.influxdata.com/influxdata-archive_compat.key
echo '393e8779c89ac8d958f81f942f9ad7fb82a25e133faddaf92e15b16e6ac9ce4c influxdata-archive_compat.key' | sha256sum -c && cat influxdata-archive_compat.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg > /dev/null
echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' | sudo tee /etc/apt/sources.list.d/influxdata.list
sudo apt-get update && sudo apt-get install influxdb
sudo systemctl unmask influxdb.service
sudo systemctl start influxdb
sudo pip3 install influxdb
```
2. create the int database
```
~$ influx
Connected to http://localhost:8086 version 1.8.10
InfluxDB shell version: 1.8.10
> show databases
name: databases
name
----
_internal
> create database int with duration 24h
> use int
Using database int
> show measurements
```
No measurements are there yet. These will be created when the data is uploaded.

### The collector
The collection of the INT data is achieved with a script that listens to the data incoming to h4 and filters the packets with the predefined expected INT. In this case these packets were predefined as UDP/1234 in the switch 3.
```
00:01:0a:00:03:05 (oui Unknown) > 00:00:0a:00:03:04 (oui Unknown), ethertype IPv4 (0x0800), length 252: 10.0.3.254.1234 > 10.0.3.4.1234: UDP, length 210
```
We used a python script to [listen and collect INT](receive/collector_influxdb.py) that parses through the INT packet and extracts the
collected information across the switches and appends to the database measurements:
* Flow latency: source IP, destination IP, source port, destination port, protocol, and the time when it was collected.
* Switch latency: switch ID, latency in its hop , and the time when it was collected.
* Link latency: egress switch ID, egress port ID, ingress switch ID, ingress portID, latency, and the time when it was collected. The latency is calculated as the difference between the time of the egress and the time of ingress on each switch.
* Queue latency: switch ID, queue ID, occupancy of the flow, and the time when it was collected.

In another terminal window, start the collector with ```sudo python3 receive/collector_influxdb.py``` 

The script also outputs to the screen as shown in Figure:

![INT packed decoded by the collector script](pictures/int_packet_decoded.png)

These measurements are appended to a Influx database running on the host machine. We can see the measurements as in Figure:

![InfluxDB client, displaying INT measurements](pictures/influxdb_CLI.png)

### Wireshark INT P4 dissector
The INT packets can be also analyzed in Wireshark, but it is helpful to have an appropriate decoder for this special packets. This decoder is called a dissector which needs to be built specifically for each implementation.

As a first approach, you may use my decoder as described in the following capture:
![capture of an INT P4 Wireshark dissector](/pictures/int_packet_udp_1234_wireshark_dissector.png)
This decoder can only be applied after the INT sink, as it applies to the INT report packet. 
Some ideas:
* [P4_Wireshark_Dissector](https://github.com/gnikol/P4-Wireshark-Dissector)
* [P4_INT_Wireshark_Dissector](https://github.com/MehmedGIT/P4_INT_Wireshark_Dissector/blob/master/int_telemetry-report.lua)

### Check InfluxDB
After having successfully generated INT stats and uploaded to the int database, you may check with:
```
~$ influx
Connected to http://localhost:8086 version 1.8.10
InfluxDB shell version: 1.8.10
> use int
> show measurements
name: measurements
name
----
flow_latency
link_latency
queue_occupancy
switch_latency



## VISUALIZATION
The visualization of the INT packets in Grafana offers quick insights of the behavior of the network. We can for example, as captured in the Figure:
* display the link latency of the flows from h1 or from h3;
* display the flow mean flow latency;
* display the same flow latency per service. In this case the HTTP, HTTPS or PostgreSQL;
* display the same flow latency per source host. In this case h1->h2 or h3->h2;
* display the switch latency overall and per switch;
![Grafana example 1](/pictures/grafana_example1.png)
### Install Grafana
Install Grafana with https://grafana.com/docs/grafana/latest/setup-grafana/installation/debian/#install-from-apt-repository
```
sudo apt-get install -y apt-transport-https
sudo apt-get install -y software-properties-common wget
sudo wget -q -O /usr/share/keyrings/grafana.key https://apt.grafana.com/gpg.key
echo "deb [signed-by=/usr/share/keyrings/grafana.key] https://apt.grafana.com stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list
sudo apt-get update
sudo apt-get install grafana
```
### Add the InfluxDB datasource
1.  In the Grafana web interface, usually ```localhost:3000/```, go to Configuration > Data sources, select InfluxDB and use the default ```http://localhost:8086```
2.  Select the database int
3.  Test and all is ok, you will see the message ![Scenario in Mininet](/pictures/graphana_influx_datasource_success.png)
### Import the dashboard
This is optional, as you can build your own dashboard.

Go to Home > Dashboards > Import dashboard and upload the [Grafana dashboard json](grafana/INT statistics.json)

![Import the dashboard](/pictures/grafana_import_dashboard.png).

Note: make sure the collector is syncronized with an ntp or rather manually syn with the command:
```
sudo date -s "00:23"
```
### Some tests
Note: the network was pre-defined with slower speed for the packets coming from h3 with bandwith commands in the [network configuration](network.py). 
So, if you do basic iperf tests from the mininet window you will get similar data as:
```
mininet> iperf h1 h2
*** Iperf: testing TCP bandwidth between h1 and h2
*** Results: ['57.0 Mbits/sec', '61.9 Mbits/sec']
mininet> iperf h3 h2
*** Iperf: testing TCP bandwidth between h3 and h2
*** Results: ['90.8 Kbits/sec', '545 Kbits/sec']
```
#### Effect of high load in INT stats
You may test the effects of sending data like the above h3>h2 and check the stats such as high latency:
![capture in graphana while flooding the server from s3 - link latency](/pictures/graphana_effect_load_link_latency.png)
![capture in graphana while flooding the server from s3 - switch latency](/pictures/graphana_effect_load_switch_latency.png)
![capture in graphana while flooding the server from s3 - flow latency](/pictures/graphana_effect_load_flow_latency.png)

In this case, at h2 we typed ```iperf -s``` and at h3 ```iperf -c 10.0.3.2 -n 100M```

## ATTACKS
The INT statistics can be an important security asset as the data may be used by the network admins for assessing the network and troubleshooting any issues. So, it is a possible target for an malicious adversary.

We consider in this scenario that an adversary is controlling a rogue host. There
are several possible attacks that we we will try such as:
* INT eavesdropping;
* INT replay;
* INT manipulation;

Etttercap is probably the best tool to do such attacks, so we needed to be acquainted with these sources:
* https://linux.die.net/man/8/ettercap
* https://github.com/Ettercap/ettercap/wiki/Providing-debug-information
* https://github.com/Ettercap/ettercap/issues/1121


### Replay attack
An attacker could easily do a replay attack by sending fake data towards the INT collector:
* collect a previous INT message or craft INT stats;
* send toward the collector;
* spoof the IP source as the s3 gateway;

In this case we have used a previously captured INT message and included into a small python script as the payload. We used the python script [send replay from h5](send/send_h5_h4.py).
```
python3 send/send_h5_h4.py --c100 --ip 10.0.3.4 --port 1234 --l4 udp
```

This replay simulated a flow coming from h1 to h2 towards the HTTP port, hence the attacker could use it to simulate a normal working status and thus hide other attack.
![Grafana replay attack](/pictures/grafana_replay_attack.png)

Some info here_ https://itecnote.com/tecnote/python-sending-specific-hex-data-using-scapy/

### INT eavesdropping
In this scenario, the adversary will try to listen to the traffic using tools like ettercap. We used ettercap to do the ARP poisoning and thus mislead both the switch as well as the host to send the data to the rogue host. This is simple MITM attack, that starts with eavesdropping:
```
ettercap -Ti h5-eth0 -M arp:oneway //10.0.3.254/ //10.0.3.4/
```
- [ ] **ONGOING**
<!-- ******************* WORK  IN PROGRESS ****************** -->

As in this current P4 code the ARP is static, the s3 and h4 ARP tables can’t be poisoned. In the Figure 4.15 we illustrate the initial h4 ARP table and that after each poisoning message from h5, s3 replies with a gratuitous ARP message:
![Failed ARP poisoning attempt](/pictures/ettercap_attack_mininet_h4_initial_arp.png)
Note: if s3 does not reply to ARP, e.g. if the tables are empty, then ettercap fails with the message:
```
FATAL: ARP poisoning needs a non empty hosts list.
```




### INT manipulation
With ettercap, we can also change the traffic in transit, however not possible due to the issue identified above

## DETECTION AND PROTECTION AGAINST ATTACKS
