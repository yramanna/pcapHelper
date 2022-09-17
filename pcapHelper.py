#pcapHelper.py

"""
Written by Yadunandan Ramanna
Github: https://github.com/yramanna
Email: yramanna@vmware.com
Note: Packet capture automation script for VMware GSS
This code has been released under the terms of the Apache-2.0 license http://opensource.org/licenses/Apache-2.0
"""

import subprocess
import os
import re

#Introduction about the flow of network packets in VMware vSphere before we begin constructing the packet capture command
subprocess.call(["clear"])
intro ='''
WELCOME TO THE INTERACTIVE PACKET CAPTURE SCRIPT!

BEFORE WE START, LET'S UNDERSTAND THE FLOW OF NETWORK PACKETS IN VSPHERE: 

     +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
     |                                                         |
     |                          ESXi HOST                      |
     |                                                         |
     |  ++++++++++++++     ++++++++++++++++++++     ++++++++++++++++++++     +++++++++++++++++++++     +++++++++++++++++
     |  |  VNIC/VMK  | --> |  VIRTUAL SWITCH  | --> | PHYSICAL UPLINK  | --> |  PHYSICAL SWITCH  | --> |  DESTINATION  |
     |  ++++++++++++++     ++++++++++++++++++++     ++++++++++++++++++++     +++++++++++++++++++++     +++++++++++++++++
     |                                                         |
     |                                                         |
     |                                                         |
     +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

> All traffic from a virtual machine network adapter or vmkernel interface goes to a virtual switch port.
> The virtual switch is software that routes traffic from a client --> a virtual machine network adapter or vmkernel interface.
> All virtual machines and vmkernel interfaces have a virtual switch port assigned to them.
> This traffic then goes to a physical adapter.
> The physical adapter is hardware that transmits traffic to the physical network.
> This is for outgoing traffic. The reverse is true for incoming traffic.
> We can capture packets at any of these levels to troubleshoot network issues within your vSphere environment.

LET'S BEGIN!'''
print(intro)

#Function to provide user a menu of all available pktcap-uw filtering options
#Only options that allow for the construction of valid packet capture commands are provided to the user. For example: User cannot filter packets by UDP ports if he/she has already filtered by TCP ports
#User can navigate the menu to apply any needed filters. Each filter can only be applied once. Menu has been designed to prevent invalid combinations of filters
#All user inputs are validated through regular expression matching
def Filters(PCAP_COMMAND):
    #Initializing filter flags to ensure a filter can only be applied once
    IP_FLAG, MAC_FLAG, VLAN_FLAG, PORT_FLAG, PROTO_FLAG=0, 0, 0, 0, 0

    #Regular expressions to match valid MAC addresses, IP addresses and port numbers
    MAC_REGEX='^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$'
    IP_REGEX='^([0-9]{1,2}|(0|1)[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|(0|1)[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|(0|1)[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|(0|1)[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    PORT_REGEX='^[0-9]{1,5}$'

    print("\n++++++++++++++++++++++++++++++\n|   PACKET CAPTURE FILTERS   |\n++++++++++++++++++++++++++++++")
    while True:
        CHOICE1=input("\nDo you want to further filter this packet capture using any of the below options? (0/1/2/3/4/5)\n0. NO\n1. PROTOCOL\n2. MAC\n3. IP\n4. VLAN\n5. PORT\n")
        if int(CHOICE1) == 0:
            break
        elif int(CHOICE1) == 1:
            if PROTO_FLAG == 0:
                while True:
                    CHOICE2=input("\nPick a protocol to filter for\n0. Return to packet filter menu\n1. ICMP\n2. TCP\n3. UDP\n4. IGMP\n")
                    if int(CHOICE2) == 0:
                        break
                    elif int(CHOICE2) == 1:
                        PROTO="0x01"
                        PCAP_COMMAND= PCAP_COMMAND+" --proto "+PROTO
                        PROTO_FLAG=1
                        break
                    elif int(CHOICE2) == 2:
                        PROTO="0x06"
                        PCAP_COMMAND= PCAP_COMMAND+" --proto "+PROTO
                        PROTO_FLAG=1
                        break
                    elif int(CHOICE2) == 3:
                        PROTO="0x11"
                        PCAP_COMMAND= PCAP_COMMAND+" --proto "+PROTO
                        PROTO_FLAG=1
                        break
                    elif int(CHOICE2) == 4:
                        PROTO="0x02"
                        PCAP_COMMAND= PCAP_COMMAND+" --proto "+PROTO
                        PROTO_FLAG=1
                        break
                    else:
                        print("\nInvalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the menu.")
            else:
                    print("\nProtocol filter has already been applied once. Please select another filter or exit this menu.")
        elif int(CHOICE1) == 2:
            if MAC_FLAG == 0:
                while True:
                    CHOICE3=input("\nYou can filter the traffic using a MAC address, or using specific source and destination MAC addresses. Please enter your choice (0/1/2/3/4)\n0. Return to packet filter menu\n1. Single MAC address\n2. Specific source MAC address\n3. Specific destination MAC address\n4. Source and destination MAC address\n")
                    if int(CHOICE3) == 0:
                        break
                    elif int(CHOICE3) == 1:
                        MAC=input("\nEnter the MAC address: ")
                        if not re.match(MAC_REGEX,MAC):
                            print("\nInvalid input. Please enter a valid MAC address.")
                        else:
                            MAC_FLAG = 1
                            PCAP_COMMAND=PCAP_COMMAND+" --mac "+MAC
                            break
                    elif int(CHOICE3) == 2:
                        S_MAC=input("\nEnter the source MAC address: ")
                        if not re.match(MAC_REGEX,S_MAC):
                            print("\nInvalid input. Please enter a valid MAC address.")
                        else:
                            MAC_FLAG = 1
                            PCAP_COMMAND=PCAP_COMMAND+" --srcmac "+S_MAC
                            break
                    elif int(CHOICE3) == 3:
                        D_MAC=input("\nEnter the destination MAC address: ")
                        if not re.match(MAC_REGEX,D_MAC):
                            print("\nInvalid input. Please enter a valid MAC address.")
                        else:
                            MAC_FLAG = 1
                            PCAP_COMMAND=PCAP_COMMAND+" --dstmac "+D_MAC
                            break
                    elif int(CHOICE3) == 4:
                        S_MAC=input("\nEnter the source MAC address: ")
                        if not re.match(MAC_REGEX,S_MAC):
                            print("\nInvalid input. Please enter a valid MAC address.")
                        else:
                            D_MAC=input("\nEnter the destination MAC address: ")
                            if not re.match(MAC_REGEX,D_MAC):
                                print("\nInvalid input. Please enter a valid MAC address.")
                            else:
                                MAC_FLAG = 1
                                PCAP_COMMAND=PCAP_COMMAND+" --srcmac "+S_MAC+" --dstmac "+D_MAC
                                break
                    else:
                        print("\nInvalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the packet filter menu.")
            else:
                print("\nMAC filter has already been applied once. Please select another filter or exit this menu.")
        elif int(CHOICE1) == 3:
            if IP_FLAG == 0:
                while True:
                    CHOICE4=input("\nYou can filter the traffic using an IP address, or using specific source and destination IP addresses. Please enter your choice (0/1/2/3/4)\n0. Return to packet filter menu\n1. Single IP address\n2. Specific source IP address\n3. Specific destination IP address\n4. Source and destination IP address\n")
                    if int(CHOICE4) == 0:
                        break
                    elif int(CHOICE4) == 1:
                        IP=input("\nEnter the IP address: ")
                        if not re.match(IP_REGEX,IP):
                            print("\nInvalid input. Please enter a valid IP address.")
                        else:
                            IP_FLAG = 1
                            PCAP_COMMAND=PCAP_COMMAND+" --ip "+IP
                            break
                    elif int(CHOICE4) == 2:
                        S_IP=input("\nEnter the source IP address: ")
                        if not re.match(IP_REGEX,S_IP):
                            print("\nInvalid input. Please enter a valid IP address.")
                        else:
                            IP_FLAG = 1
                            PCAP_COMMAND=PCAP_COMMAND+" --srcip "+S_IP
                            break
                    elif int(CHOICE4) == 3:
                        D_IP=input("\nEnter the destination IP address: ")
                        if not re.match(IP_REGEX,D_IP):
                            print("\nInvalid input. Please enter a valid IP address.")
                        else:
                            IP_FLAG = 1
                            PCAP_COMMAND=PCAP_COMMAND+" --dstip "+D_IP
                            break
                    elif int(CHOICE4) == 4:
                        S_IP=input("\nEnter the source IP address: ")
                        if not re.match(IP_REGEX,S_IP):
                            print("\nInvalid input. Please enter a valid IP address.")
                        else:
                            D_IP=input("\nEnter the destination IP address: ")
                            if not re.match(IP_REGEX,D_IP):
                                print("\nInvalid input. Please enter a valid IP address.")
                            else:
                                IP_FLAG = 1
                                PCAP_COMMAND=PCAP_COMMAND+" --srcmac "+S_IP+" --dstmac "+D_IP
                                break
                    else:
                        print("\nInvalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the packet filter menu.")
            else:
                print("\nIP filter has already been applied once. Please select another filter or exit this menu.")
        elif int(CHOICE1) == 4:
            if VLAN_FLAG == 0:
                while True:
                    VLAN_ID = input("\nEnter the VLAN ID: ")
                    if not re.match('[0-9]{1,4}$',VLAN_ID) or int(VLAN_ID) > 4094:
                        print("\nInvalid input. Please enter a valid VLAN ID.")
                    else:
                        VLAN_FLAG = 1
                        PCAP_COMMAND=PCAP_COMMAND+" --vlan "+VLAN_ID
                else:
                    print("\nVLAN filter has already been applied once. Please select another filter or exit this menu.")
        elif int(CHOICE1) == 5:
            if PORT_FLAG == 0:
                while True and PORT_FLAG == 0:
                    PORT_CHOICE = input("\nChoose the type of port you want to filter packets with (0/1/2)\n0. Return to main packet filter menu.\n1. TCP port\n2. UDP port\n")
                    if int(PORT_CHOICE) == 0:
                        break
                    elif int(PORT_CHOICE) == 1:
                        while True:
                            CHOICE5 = input("\nYou can filter the traffic using a TCP port, or using specific source and destination TCP ports. Please enter your choice (0/1/2/3/4)\n0. Back\n1. Single TCP port\n2. Specific source TCP port\n3. Specific destination TCP port\n4. Source and destination TCP port\n")
                            if int(CHOICE5) == 0:
                                break
                            elif int(CHOICE5) == 1:
                                PORT = input("\nEnter the TCP port: ")
                                if not re.match(PORT_REGEX, PORT):
                                    print("\nInvalid input. Please enter a valid TCP port.")
                                else:
                                    PORT_FLAG= 1
                                    PCAP_COMMAND=PCAP_COMMAND+" --tcpport "+PORT
                                    break
                            elif int(CHOICE5) == 2:
                                S_PORT = input("\nEnter the source TCP port: ")
                                if not re.match(PORT_REGEX, S_PORT):
                                    print("\nInvalid input. Please enter a valid TCP port.")
                                else:
                                    PORT_FLAG= 1
                                    PCAP_COMMAND=PCAP_COMMAND+" --srctcpport "+S_PORT
                                    break
                            elif int(CHOICE5) == 3:
                                D_PORT = input("\nEnter the destination TCP port: ")
                                if not re.match(PORT_REGEX, D_PORT):
                                    print("\nInvalid input. Please enter a valid TCP port.")
                                else:
                                    PORT_FLAG= 1
                                    PCAP_COMMAND=PCAP_COMMAND+" --dsttcpport "+D_PORT
                                    break
                            elif int(CHOICE5) == 4:
                                S_PORT=input("\nEnter the source TCP port: ")
                                if not re.match(PORT_REGEX, PORT):
                                    print("\nInvalid input. Please enter a valid TCP port.")
                                else:
                                    D_PORT=input("\nEnter the destination TCP port: ")
                                    if not re.match(PORT_REGEX, PORT):
                                        print("\nInvalid input. Please enter a valid TCP port.")
                                    else:
                                        PORT_FLAG = 0
                                        PCAP_COMMAND=PCAP_COMMAND+" --srctcpport "+S_PORT+" --dsttcpport "+D_PORT
                                        break
                            else:
                                print("\nInvalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the port type menu.")
                    elif int(PORT_CHOICE) == 2:
                        while True:
                            CHOICE5 = input("\nYou can filter the traffic using a UDP port, or using specific source and destination UDP ports. Please enter your choice (0/1/2/3/4)\n0. Back\n1. Single UDP port\n2. Specific source UDP port\n3. Specific destination UDP port\n4. Source and destination UDP port\n")
                            if int(CHOICE5) == 0:
                                break
                            elif int(CHOICE5) == 1:
                                PORT = input("\nEnter the UDP port: ")
                                if not re.match(PORT_REGEX, PORT):
                                    print("\nInvalid input. Please enter a valid UDP port.")
                                else:
                                    PORT_FLAG= 1
                                    PCAP_COMMAND=PCAP_COMMAND+" --udpport "+PORT
                                    break
                            elif int(CHOICE5) == 2:
                                S_PORT = input("\nEnter the source UDP port: ")
                                if not re.match(PORT_REGEX, S_PORT):
                                    print("\nInvalid input. Please enter a valid UDP port.")
                                else:
                                    PORT_FLAG= 1
                                    PCAP_COMMAND=PCAP_COMMAND+" --srcudpport "+S_PORT
                                    break
                            elif int(CHOICE5) == 3:
                                D_PORT = input("\nEnter the destination UDP port: ")
                                if not re.match(PORT_REGEX, D_PORT):
                                    print("\nInvalid input. Please enter a valid UDP port.")
                                else:
                                    PORT_FLAG= 1
                                    PCAP_COMMAND=PCAP_COMMAND+" --dstudpport "+D_PORT
                                    break
                            elif int(CHOICE5) == 4:
                                S_PORT=input("\nEnter the source UDP port: ")
                                if not re.match(PORT_REGEX, PORT):
                                    print("\nInvalid input. Please enter a valid UDP port.")
                                else:
                                    D_PORT=input("\nEnter the destination UDP port: ")
                                    if not re.match(PORT_REGEX, PORT):
                                        print("\nInvalid input. Please enter a valid UDP port.")
                                    else:
                                        PORT_FLAG = 0
                                        PCAP_COMMAND=PCAP_COMMAND+" --srcudpport "+S_PORT+" --dstudpport "+D_PORT
                                        break
                            else:
                                print("\nInvalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the port type menu.")
                    else:
                        print("\nInvalid input. Please choose an option between 1-2.")
            else:
                print("\nPort filter has already been applied once. Please select another filter or exit this menu.")
        else:
            print("\nInvalid input. Please choose an option between 1-5 from the above list. Enter 0 to exit the packet filter menu.")
    return PCAP_COMMAND

#Function to input the packet capture point
def Point():
    print("\n++++++++++++++++++++++++++++++\n|    PACKET CAPTURE LEVEL    |\n++++++++++++++++++++++++++++++")
    while True:
        CAP_POINT=input("\nChoose the packet capture point (1/2/3/4)\n1. vmkernel interface\n2. virtual network adapter\n3. virtual switch port\n4. hardware network adapter/uplink\n")
        if not re.match('^[1-4]$', CAP_POINT):
            print("\nInvalid input. Please choose an option between 1-4.")
        else:
            break
    return CAP_POINT

#Function to input the packet capture direction
def Direction():
    print("\n++++++++++++++++++++++++++++++\n|  PACKET CAPTURE DIRECTION  |\n++++++++++++++++++++++++++++++")
    while True:
        VERSION=subprocess.run("vmware -vl | grep -oe [567]\.[057] | head -1", shell=True, stdout=subprocess.PIPE)
        if VERSION.stdout.decode()[0:-1] == "7.0" or VERSION.stdout.decode()[0:-1] == "6.7":
            DIR=input("\nChoose the direction you want to capture packets in (1/2/3)\n1. Incoming\n2. Outgoing\n3. Both\n")
            if not re.match('^[1-3]$', DIR):
                print("\nInvalid input. Please choose an option between 1-3.")
            else:
                break
        else:
            DIR=input("\nChoose the direction you want to capture packets in (1/2)\n1. Incoming\n2. Outgoing\n")
            if not re.match('^[1-2]$', DIR):
                print("\nInvalid input. Please choose an option between 1-2.")
            else:
                break
    return DIR

#Function to input the packet capture duration
def Duration(PCAP_COMMAND):
    print("\n++++++++++++++++++++++++++++++\n|   PACKET CAPTURE DURATION  |\n++++++++++++++++++++++++++++++")
    while True:
        TIME_CHOICE=input("\nChoose the duration you want to capture packets for (1/3)\n1. 3 minutes\n2. 1 hour\n3. Continuous (captures packets continuously until script is terminated)\n")
        if not re.match('^[1-3]$', TIME_CHOICE):
            print("\nInvalid input. Please choose an option between 1-3.")
        elif int(TIME_CHOICE) == 1:
            PCAP_TIME = 1
            break
        elif int(TIME_CHOICE) > 1:
            PCAP_TIME = 20
            print("\n++++++++++++++++++++++++++++++\n|     PACKET CAPTURE SIZE    |\n++++++++++++++++++++++++++++++")
            SIZE_CHOICE = input("\nDo you wish to limit the total datastore space required to capture packets for this duration? If yes, please note that some packets might not be captured (1/2)\n1. Yes\n2. No\n")
            if SIZE_CHOICE == '1':
                PCAP_SIZE=input("\nEnter the total size you want to limit the packet capture files to. The value must be entered in MB: ")
                PCAP_SIZE_PER_FILE=max(1,int(PCAP_SIZE)//20)
                PCAP_COMMAND=PCAP_COMMAND+" -C "+str(PCAP_SIZE_PER_FILE)
            break
    return [PCAP_COMMAND, PCAP_TIME]

#Function to input the location to save the packet capture file(s) in
def Directory(PCAP_COMMAND, DIR_TXT, CAP_POINT_TXT, CLIENT):
    print("\n++++++++++++++++++++++++++++++\n|  PACKET CAPTURE DIRECTORY  |\n++++++++++++++++++++++++++++++")
    while True:
        DIRECTORY=input("Enter the full path to the directory you want to save the packet capture file(s) in: ")
        if DIRECTORY == "":
            DIRECTORY=subprocess.call(["pwd"])
            PCAP_COMMAND=PCAP_COMMAND+" -s 150 -o "+DIRECTORY+"/"+CAP_POINT_TXT+"_"+CLIENT+"_"+DIR_TXT+"_1.pcap"
            break
        elif os.path.isdir(DIRECTORY):
            PCAP_COMMAND=PCAP_COMMAND+" -s 150 -o "+DIRECTORY+"/"+CAP_POINT_TXT+"_"+CLIENT+"_"+DIR_TXT+"_1.pcap"
            break
        elif os.path.isdir("/"+DIRECTORY):
            PCAP_COMMAND=PCAP_COMMAND+" -s 150 -o /"+DIRECTORY+"/"+CAP_POINT_TXT+"_"+CLIENT+"_"+DIR_TXT+"_1.pcap"
            break
        else:
            print("Invalid input. Please enter a valid directory. Do not enter the filename.")
    return PCAP_COMMAND

#Main code

#Get the packet capture point
CAP_POINT=Point()

#Initialize string variables to construct the packet capture command
DIR_TXT = ''
PCAP_COMMAND = ''

#Based on the level of packet capture, we start constructing the packet capture command
#Packet capture command is a string variable that is constructed using user inputs
#We then call the Filters() function to allow the user to filter packets as needed
while True:
    if int(CAP_POINT) == 1:
        CAP_POINT_TXT="vmkernel"
        #Ensure the value entered is a valid vmkernel interface
        print()
        subprocess.call("net-stats -l | head -1", shell=True)
        subprocess.call("net-stats -l | grep vmk", shell=True)
        print()
        CLIENT=input("Enter the name of a vmkernel interface from the ClientName column in the above list. This is case sensitive: ")
        if subprocess.run("net-stats -l | grep vmk | awk '{print $6}' | grep -x "+CLIENT+" | wc -l", shell=True, stdout=subprocess.PIPE).stdout.decode()[0:-1] == '0':
            print("\nInvalid input. Please enter a valid vmkernel interface from the list. Run the script once more if you wish to choose a different capture point.")
        else:
            #Add capture point to the command
            PCAP_COMMAND="pktcap-uw --vmk "+CLIENT
            #Input packet capture direction and add it to the command
            DIR=int(Direction())
            if DIR == 1:
                PCAP_COMMAND=PCAP_COMMAND+" --capture PortOutput"
                DIR_TXT="incoming"
            elif DIR == 2:
                PCAP_COMMAND=PCAP_COMMAND+" --capture PortInput"
                DIR_TXT="outgoing"
            elif DIR == 3:
                PCAP_COMMAND=PCAP_COMMAND+" --dir 2"
                DIR_TXT="bidirectional"
            break
    elif int(CAP_POINT) == 2:
        CAP_POINT_TXT="vnic"
        #Ensure the value entered is a valid virtual machine network adapter switchport
        print()
        subprocess.call("net-stats -l | grep -vE 'vmk|vmnic|lag'", shell=True)
        print()
        CLIENT=input("Enter the port number of the specific virtual machine network adapter from the PortNum column in the above list: ")
        if subprocess.run("net-stats -l | grep -vE 'vmk|vmnic|lag' | awk '{print $1}' | grep -x "+CLIENT+" | wc -l", shell=True, stdout=subprocess.PIPE).stdout.decode()[0:-1] == '0':
            print("\nInvalid input. Please enter a valid port number from the list. Run the script once more if you wish to choose a different capture point.")
        else:
            #Add capture point to the command
            PCAP_COMMAND="pktcap-uw --switchport "+CLIENT
            #Input packet capture direction and add it to the command
            DIR=int(Direction())
            if DIR == 1:
                PCAP_COMMAND=PCAP_COMMAND+" --capture vNicRx"
                DIR_TXT="incoming"
            elif DIR == 2:
                PCAP_COMMAND=PCAP_COMMAND+" --capture vNicTx"
                DIR_TXT="outgoing"
            elif DIR == 3:
                PCAP_COMMAND=PCAP_COMMAND+" --capture VnicRx,vNicTx"
                DIR_TXT="bidirectional"
            #Update CLIENT to reflect the name of the virtual machine network adapter
            CLIENT=subprocess.run("net-stats -l | grep "+CLIENT+" | awk '{print $6}'", shell=True, stdout=subprocess.PIPE).stdout.decode()[0:-1]
            break
    elif int(CAP_POINT) == 3:
        CAP_POINT_TXT="switchport"
        #Ensure the value entered is a valid virtual switchport
        print()
        subprocess.call("net-stats -l", shell=True)
        print()
        CLIENT=input("Enter the port number of the specific virtual machine network adapter or vmkernel interface from the PortNum column in the above list: ")
        if subprocess.run("net-stats -l | awk '{print $1}' | grep -x "+CLIENT+" | wc -l", shell=True, stdout=subprocess.PIPE).stdout.decode()[0:-1] == '0':
            print("\nInvalid input. Please enter a valid port number from the list. Run the script once more if you wish to choose a different capture point.")
        else:
            #Add capture point to the command
            PCAP_COMMAND="pktcap-uw --switchport "+CLIENT
            #Input packet capture direction and add it to the command
            DIR=int(Direction())
            if DIR == 1:
                PCAP_COMMAND=PCAP_COMMAND+" --capture PortOutput"
                DIR_TXT="incoming"
            elif DIR == 2:
                PCAP_COMMAND=PCAP_COMMAND+" --capture PortInput"
                DIR_TXT="outgoing"
            elif DIR == 3:
                PCAP_COMMAND=PCAP_COMMAND+" --dir 2"
                DIR_TXT="bidirectional"
                CLIENT=subprocess.call(["net-stats","-l","|","grep","-i",CLIENT,"|","awk","'{print","$6}'"])
            break
    elif int(CAP_POINT) == 4:
        CAP_POINT_TXT="uplink"
        #Ensure the value entered is a valid physical uplink
        print()
        subprocess.call("net-stats -l | head -1", shell=True)
        subprocess.call("net-stats -l | grep vmnic", shell=True)
        print()
        CLIENT=input("Enter the name of a hardware uplink from the ClientName column in the above list. This is case sensitive: ")
        if subprocess.run("net-stats -l | grep vmnic | awk '{print $6}' | grep -x "+CLIENT+" | wc -l", shell=True, stdout=subprocess.PIPE).stdout.decode()[0:-1] == '0':
            print("\nInvalid input. Please enter a valid hardware uplink from the list. Run the script once more if you wish to choose a different capture point.")
        else:
            #Add capture point to the command
            PCAP_COMMAND="pktcap-uw --uplink "+CLIENT
            #Input packet capture direction and add it to the command
            DIR=int(Direction())
            if DIR == 1:
                PCAP_COMMAND=PCAP_COMMAND+" --capture UplinkRcvKernel"
                DIR_TXT="incoming"
            elif DIR == 2:
                PCAP_COMMAND=PCAP_COMMAND+" --capture UplinkSndKernel"
                DIR_TXT="outgoing"
            elif DIR == 3:
                PCAP_COMMAND=PCAP_COMMAND+" --dir 2"
                DIR_TXT="bidirectional"
            break
            
#The functions Filters, Duration and Directory are called to complete construction of the packet capture command
PCAP_COMMAND=Filters(PCAP_COMMAND)
PCAP_COMMAND, PCAP_TIME=Duration(PCAP_COMMAND)
PCAP_COMMAND=Directory(PCAP_COMMAND, DIR_TXT, CAP_POINT_TXT, CLIENT)

#We confirm that the packet packet capture command has been constructed successfully and print the command for documentation
print("\nThanks for the inputs! Capturing packets now using the command: ",PCAP_COMMAND)
print("If you wish to stop capturing packets, press CTRL+C to terminate the script.\n")
print("****************************************************************************\n")

#We then execute the packet capture command depending on the duration chosen by the user
if PCAP_TIME < 3:
    for STAMP in range(1,PCAP_TIME+1):
        #Incrementing file number to sustain packet sequence across files
        PCAP_COMMAND=PCAP_COMMAND[:-(6+len(str(STAMP)))]+"_"+str(STAMP)+".pcap"
        COMMAND="eval "+PCAP_COMMAND+" & sleep 180"
        subprocess.call(COMMAND, shell=True)
        subprocess.call("pkill pktcap-uw", shell=True)
else:
    while True:
        for STAMP in range(1,PCAP_TIME+1):
            #Incrementing file number to sustain packet sequence across files
            PCAP_COMMAND=PCAP_COMMAND[:-(6+len(str(STAMP)))]+"_"+str(STAMP)+".pcap"
            COMMAND="eval "+PCAP_COMMAND+" & sleep 180"
            subprocess.call(COMMAND, shell=True)
            subprocess.call("pkill pktcap-uw", shell=True)

#End of script
