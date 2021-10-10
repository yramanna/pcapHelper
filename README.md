# Packet capture automation script

Designed to help capture packets in VMware vSphere ESXi hosts. The script makes use of the pktcap-uw tool that is in-built in ESXi hosts.

The script allows packet captures at the below levels:
1. ESXi host VMkernel adapter
2. ESXi host hardware adapter 
3. Virtual machine network adapter
4. Virtual switch port

You can capture packets for durations of 3 minutes, 1 hour or continuosly until terminated.
The script also validates all user inputs to ensure only valid pktcap-uw commands are generated.

