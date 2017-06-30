# SNMP Covert Channel - Chat
This script is a client-to-client chat and the messages travel by a covert channel in the SNMP protocol. To achive this communication, it uses functions from the Scapy program.

## Motivation
This script has been developed to fulfill a practical work of the subject Network Security I, part of the UBA's Information Security career. It is for academic purposes.

## Installation
Install the requirements needed through this command:
```
pip install -r requirements.txt
```

In addition, Tkinter is needed:
```
apt-get install python-tk
```

## Usage
To run the script, just execute the following command in the directory where you downloaded this repository.
```
python chat_snmp.py -l LOCAL_IP -d DEST_IP
```
As optional, you can choose the SNMP community to use in the conversation. The default is "UBAMSI".

### Usage example
Input
```
sudo python chat_snmp.py -l 192.168.0.10 -d 192.168.0.86 -c SECURITY
```


## Authors
* Bernardi, Ignacio David
* Sena, Matias Ezequiel
* Sgrinzi, Agustina Elisabet

## Relevant links
For more information about this covert channel, you can visit the following websites:
* [Scapy](http://www.secdev.org/projects/scapy/)
* [SNMPChat: Chatear en un canal encubierto sobre SNMP](http://www.elladodelmal.com/2016/05/snmpchat-chatear-en-un-canal-encubierto.html)
