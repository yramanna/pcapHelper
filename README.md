# Packet capture automation script

Designed to help capture packets in VMware vSphere ESXi hosts. The script makes use of the pktcap-uw tool that is in-built in ESXi hypervisors.

The script allows packet captures at the below capture points:
1. ESXi host VMkernel adapter
2. ESXi host hardware adapter 
3. Virtual machine network adapter
4. Virtual switch port

You can capture packets for durations of 3 minutes, 1 hour or continuosly until terminated. You can also apply filters to capture the required packets, specify capture direction and limit file size.

The script validates all user inputs to ensure only valid pktcap-uw commands are generated.
