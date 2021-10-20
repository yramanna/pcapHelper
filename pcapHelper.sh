#pcapHelper.sh
#!/bin/sh

"""
Written by Yadunandan Ramanna
Github: https://github.com/yramanna
Email: yramanna@vmware.com
Note: Packet capture automation script for VMware GSS 
This code has been released under the terms of the Apache-2.0 license http://opensource.org/licenses/Apache-2.0
"""

#Introduction about the flow of network packets in VMware vSphere before we begin constructing the packet capture command
clear
echo "
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

LET'S BEGIN!"

#Function to provide user a menu of all available pktcap-uw filtering options
#Only options that allow for the construction of valid packet capture commands are provided to the user. For example: User cannot filter packets by UDP ports if he/she has already filtered by TCP ports
#User can navigate the menu to apply any needed filters. Each filter can only be applied once. Menu has been designed to prevent invalid combinations of filters
#All user inputs are validated through regular expression matching
Filters(){
    echo "
++++++++++++++++++++++++++++++
|   PACKET CAPTURE FILTERS   |
++++++++++++++++++++++++++++++"
    while true; do
        echo "
Do you want to further filter this packet capture using any of the below options? (0/1/2/3/4/5)
0. NO
1. PROTOCOL
2. MAC
3. IP
4. VLAN
5. PORT"
        read ANSWER
        case $ANSWER in
            0 ) break ;;
            1 ) if [ $PROTO_FLAG = False ]; then
                    while true; do
                    echo "
Pick a protocol to filter for
0. Return to packet filter menu
1. ICMP
2. TCP
3. UDP
4. IGMP"
                    read CHOICE
                    case $CHOICE in
                        0 ) break ;;
                        1 ) PROTO="0x01"; PCAP_COMMAND=" ${PCAP_COMMAND} --proto ${PROTO}"; PROTO_FLAG=True; break ;;
                        2 ) PROTO="0x06"; PCAP_COMMAND=" ${PCAP_COMMAND} --proto ${PROTO}"; PROTO_FLAG=True; break ;;
                        3 ) PROTO="0x11"; PCAP_COMMAND=" ${PCAP_COMMAND} --proto ${PROTO}"; PROTO_FLAG=True; break ;;
                        4 ) PROTO="0x02"; PCAP_COMMAND=" ${PCAP_COMMAND} --proto ${PROTO}"; PROTO_FLAG=True; break ;;
                        * ) echo ""
                            echo "Invalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the menu." 
                            ;;
                    esac
                    done
                else
                    echo ""
                    echo "Protocol filter has already been applied once. Please select another filter or exit this menu."
                fi
                ;;

            2 ) if [ $MAC_FLAG = False ]; then				
                while true; do
                echo "
You can filter the traffic using a MAC address, or using specific source and destination MAC addresses. Please enter your choice (0/1/2/3/4)
0. Return to packet filter menu
1. Single MAC address
2. Specific source MAC address
3. Specific destination MAC address
4. Source and destination MAC address"
                read CHOICE
                case $CHOICE in
                    0 ) break ;;
                    1 ) read -p "Enter the MAC address: " MAC
                        if [ ! $(echo "$MAC" | grep -xE $MAC_REGEX ) ]; then
                            echo ""
                            echo "Invalid input. Please enter a valid MAC address."
                        else
                            MAC_FLAG=True
                            PCAP_COMMAND=" ${PCAP_COMMAND} --mac ${MAC}"
                            break
                        fi
                        ;;
                    2 ) read -p "Enter the source MAC address: " S_MAC
                        if [ ! $(echo "$S_MAC" | grep -xE $MAC_REGEX ) ]; then
                            echo ""
                            echo "Invalid input. Please enter a valid MAC address."
                        else
                            MAC_FLAG=True
                            PCAP_COMMAND=" ${PCAP_COMMAND} --srcmac ${S_MAC}"
                            break
                        fi
                        ;;
                    3 ) read -p "Enter the destination MAC address: " D_MAC
                        if [ ! $(echo "$D_MAC" | grep -xE $MAC_REGEX ) ]; then
                            echo ""
                            echo "Invalid input. Please enter a valid MAC address."
                        else
                            MAC_FLAG=True
                            PCAP_COMMAND=" ${PCAP_COMMAND} --dstmac ${D_MAC}"
                            break
                        fi
                        ;;
                    4 ) read -p "Enter the source MAC address: " S_MAC
                        if [ ! $(echo "$S_MAC" | grep -xE $MAC_REGEX ) ]; then
                            echo ""
                            echo "Invalid input. Please enter a valid MAC address."
                        else
                            MAC_FLAG=True
                            PCAP_COMMAND=" ${PCAP_COMMAND} --srcmac ${S_MAC}"
                            read -p "Enter the destination MAC address: " D_MAC
                            if [ ! $(echo "$D_MAC" | grep -xE $MAC_REGEX ) ]; then
                                echo ""
                                echo "Invalid input. Packets will only be filtered by source MAC address."
                                break
                            else
                                PCAP_COMMAND=" ${PCAP_COMMAND} --dstmac ${D_MAC}"
                                break
                            fi
                        fi
                        ;;
                    * ) echo ""
                        echo "Invalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the packet filter menu."
                    esac
                done
                else
                    echo ""
                    echo "MAC filter has already been applied once. Please select another filter or exit this menu."
                fi
                ;;

            3 ) if [ $IP_FLAG = False ]; then
                    while true; do
                    echo "
You can filter the traffic using an IP address, or using specific source and destination IP addresses. Please enter your choice (0/1/2/3/4)
0. Return to packet filter menu
1. Single IP address
2. Specific source IP address
3. Specific destination IP address
4. Source and destination IP address"
                    read CHOICE
                    case $CHOICE in
                        0 ) break ;;
                        1 ) read -p "Enter the IP address: " IP
                            if [ ! $(echo "$IP" | grep -xE $IP_REGEX ) ]; then
                                echo ""
                                echo "Invalid input. Please enter a valid IP address."
                            else
                                IP_FLAG=True
                                PCAP_COMMAND=" ${PCAP_COMMAND} --ip ${IP}"
                                break
                            fi
                            ;;
                        2 ) read -p "Enter the source MAC address: " S_IP
                            if [ ! $(echo "$S_IP" | grep -xE $IP_REGEX ) ]; then
                                echo ""
                                echo "Invalid input. Please enter a valid IP address."
                            else
                                IP_FLAG=True
                                PCAP_COMMAND=" ${PCAP_COMMAND} --srcip ${S_IP}"
                                break
                            fi
                            ;;
                        3 ) read -p "Enter the destination MAC address: " D_IP
                            if [ ! $(echo "$D_IP" | grep -xE $IP_REGEX ) ]; then
                                echo ""
                                echo "Invalid input. Please enter a valid IP address."
                            else
                                IP_FLAG=True
                                PCAP_COMMAND=" ${PCAP_COMMAND} --dstip ${D_IP}"
                                break
                            fi
                            ;;
                        4 ) read -p "Enter the source IP address: " S_IP
                            if [ ! $(echo "$S_IP" | grep -xE $IP_REGEX ) ]; then
                                echo ""
                                echo "Invalid input. Please enter a valid IP address."
                            else
                                IP_FLAG=True
                                PCAP_COMMAND=" ${PCAP_COMMAND} --srcip ${S_IP}"
                                read -p "Enter the destination IP address: " D_IP
                                if [ ! $(echo "$D_IP" | grep -xE $IP_REGEX ) ]; then
                                    echo ""
                                    echo "Invalid input. Packets will only be filtered by source IP address."
                                    break
                                else
                                    PCAP_COMMAND=" ${PCAP_COMMAND} --dstip ${D_IP}"
                                    break
                                fi
                            fi
                            ;;
                        * ) echo ""
                            echo "Invalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the packet filter menu."
                    esac
                    done
                else
                    echo ""
                    echo "IP filter has already been applied once. Please select another filter or exit this menu."
                fi
                ;;

            4 ) if [ $VLAN_FLAG = False ]; then
                    read -p "Enter the VLAN ID: " VLAN_ID
                    if [ ! $(echo "$VLAN_ID" | grep -xE '^[0-9]{1,4}$') ] || [ $VLAN_ID -gt 4094 ]; then
                        echo ""
                        echo "Invalid input. Please enter a valid VLAN ID."					
                    else
                        VLAN_FLAG=True
                        PCAP_COMMAND=" ${PCAP_COMMAND} --vlan ${VLAN}"
                    fi
                else
                    echo ""
                    echo "VLAN filter has already been applied once. Please select another filter or exit this menu."
                fi
                ;;
                        
            5 ) if [ $PORT_FLAG = False ]; then
                    while true; do
                    echo "
Choose the type of port you want to filter packets with (0/1/2) 
0. Return to main packet filter menu
1. TCP port
2. UDP port"
                    read PORT_CHOICE
                    case $PORT_CHOICE in
                        0 ) break ;;
                        1 )	while true; do
                            echo "
You can filter the traffic using a TCP port, or using specific source and destination TCP ports. Please enter your choice (0/1/2/3/4)
0. Back
1. Single TCP port
2. Specific source TCP port
3. Specific destination TCP port
4. Source and destination TCP port"
                            read CHOICE
                            case $CHOICE in
                                0 ) break ;;
                                1 ) read -p "Enter the TCP port: " PORT
                                    if [ ! $(echo "$PORT" | grep -xE $PORT_REGEX ) ]; then
                                        echo ""
                                        echo "Invalid input. Please enter a valid TCP port."
                                    else
                                        PORT_FLAG=True
                                        PCAP_COMMAND=" ${PCAP_COMMAND} --tcpport ${PORT}"
                                        break
                                    fi
                                    ;;
                                2 )	read -p "Enter the source TCP port: " S_PORT
                                    if [ ! $(echo "$S_PORT" | grep -xE $PORT_REGEX ) ]; then
                                        echo ""
                                        echo "Invalid input. Please enter a valid TCP port."
                                    else
                                        PORT_FLAG=True
                                        PCAP_COMMAND=" ${PCAP_COMMAND} --srctcpport ${S_PORT}"
                                        break
                                    fi
                                    ;;
                                3 ) read -p "Enter the destination TCP port: " D_PORT
                                    if [ ! $(echo "$D_PORT" | grep -xE $PORT_REGEX ) ]; then
                                        echo ""
                                        echo "Invalid input. Please enter a valid TCP port."
                                    else
                                        PORT_FLAG=True
                                        PCAP_COMMAND=" ${PCAP_COMMAND} --dsttcpport ${D_PORT}"
                                        break
                                    fi
                                    ;;
                                4 ) read -p "Enter the source TCP port: " S_PORT
                                    if [ ! $(echo "$S_PORT" | grep -xE $PORT_REGEX ) ]; then
                                        echo ""
                                        echo "Invalid input. Please enter a valid TCP port."
                                    else
                                        PORT_FLAG=True
                                        PCAP_COMMAND=" ${PCAP_COMMAND} --srctcpport ${S_PORT}"
                                        read -p "Enter the destination TCP port: " D_PORT
                                        if [ ! $(echo "$D_PORT" | grep -xE $PORT_REGEX ) ]; then
                                            echo ""
                                            echo "Invalid input. Packets will only be filtered by source TCP port."
                                            break
                                        else
                                            PCAP_COMMAND=" ${PCAP_COMMAND} --dsttcpport ${D_PORT}"
                                            break
                                        fi
                                    fi
                                    ;;
                                * ) echo ""	
                                    echo "Invalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the port type menu."
                                    ;;
                            esac
                            done
                            break
                            ;;
                        2 )	while true; do
                            echo "
You can filter the traffic using a UDP port, or using specific source and destination UDP ports. Please enter your choice (0/1/2/3/4)
0. Back
1. Single UDP port
2. Specific source UDP port
3. Specific destination UDP port
4. Source and destination UDP port"
                            read CHOICE
                            case $CHOICE in
                                0 ) break ;;
                                1 ) read -p "Enter the UDP port: " UDP_PORT
                                    if [ ! $(echo "$UDP_PORT" | grep -xE $PORT_REGEX ) ]; then
                                        echo ""
                                        echo "Invalid input. Please enter a valid UDP port."
                                    else
                                        PORT_FLAG=True
                                        PCAP_COMMAND=" ${PCAP_COMMAND} --udpport ${UDP_PORT}"
                                        break
                                    fi
                                    ;;
                                2 ) read -p "Enter the source UDP port: " S_UDP_PORT
                                    if [ ! $(echo "$S_UDP_PORT" | grep -xE $PORT_REGEX ) ]; then
                                        echo ""
                                        echo "Invalid input. Please enter a valid UDP port."
                                    else
                                        PORT_FLAG=True
                                        PCAP_COMMAND=" ${PCAP_COMMAND} --srcudpport ${S_UDP_PORT}"
                                        break
                                    fi
                                    ;;
                                3 )     read -p "Enter the destination UDP port: " D_UDP_PORT
                                    if [ ! $(echo "$D_UDP_PORT" | grep -xE $PORT_REGEX ) ]; then
                                        echo ""
                                        echo "Invalid input. Please enter a valid UDP port."
                                    else
                                        PORT_FLAG=True
                                        PCAP_COMMAND=" ${PCAP_COMMAND} --dstudpport ${D_UDP_PORT}"
                                        break
                                    fi
                                    ;;
                                4 ) read -p "Enter the source UDP port: " S_UDP_PORT
                                    if [ ! $(echo "$S_UDP_PORT" | grep -xE $PORT_REGEX ) ]; then
                                        echo ""
                                        echo "Invalid input. Please enter a valid UDP port."
                                    else
                                        PORT_FLAG=True
                                        PCAP_COMMAND=" ${PCAP_COMMAND} --srcudpport ${S_UDP_PORT}"
                                        read -p "Enter the destination UDP port: " D_UDP_PORT
                                        if [ ! $(echo "$D_UDP_PORT" | grep -xE $PORT_REGEX ) ]; then
                                            echo ""
                                            echo "Invalid input. Packets will only be filtered by source UDP port."
                                            break
                                        else
                                            PCAP_COMMAND=" ${PCAP_COMMAND} --dstudpport ${D_UDP_PORT}"
                                            break
                                        fi
                                    fi
                                    ;;
                                * ) echo ""
                                    echo "Invalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the port type menu."
                                        ;;
                            esac
                            done
                            break
                            ;;
                        * ) echo ""
                            echo "Invalid input. Please choose an option between 1-2."
                            ;;
                    esac
                    done
                else
                    echo ""
                    echo "Port filter has already been applied once. Please select another filter or exit this menu."
                fi
                ;;
				
            * ) echo ""
                echo "Invalid input. Please choose an option between 1-5 from the above list. Enter 0 to exit the packet filter menu."
                ;;
        esac
    done
}

#Function to input the level of packet capture
Level(){
    echo "
++++++++++++++++++++++++++++++
|    PACKET CAPTURE LEVEL    |
++++++++++++++++++++++++++++++"
    while true; do
        echo "
Choose the level you want to capture packets at (1/2/3/4)
1. vmkernel interface
2. virtual network adapter
3. virtual switch port
4. hardware network adapter/uplink"
        read CAP_POINT
        if [ ! $(echo "$CAP_POINT" | grep -xE '^[1-4]$') ]; then
            echo ""
            echo "Invalid input. Please choose an option between 1-4."
        else
            break
        fi
    done
}

#Function to input the direction of packet capture
Direction(){
    echo "
++++++++++++++++++++++++++++++
|  PACKET CAPTURE DIRECTION  |
++++++++++++++++++++++++++++++"
    while true; do
        VERSION="$(vmware -vl | grep -oe [567]\.[057] | head -1)"
        if [ "$VERSION" > 6.6 ]; then
            echo ""
            echo "Choose the direction you want to capture packets in (1/2/3)
1. Incoming
2. Outgoing
3. Both"
            read DIR
            if [ ! $(echo "$DIR" | grep -xE '^[1-3]$') ]; then
                echo ""
                echo "Invalid input. Please choose an option between 1-3."
            else
                break
            fi
        else
            echo ""
            echo "Choose the direction you want to capture packets in (1/2)
1. Incoming
2. Outgoing"
            read DIR
            if [ ! $(echo "$DIR" | grep -xE '^[1-2]$') ]; then
                echo ""
                echo "Invalid input. Please choose an option between 1-2."
            else 
                break
            fi
        fi
    done
}

#Special function to input the direction of packet capture for virtual machine vnics
#There is no command to capture both incoming and outgoing packets at the same time for a virtual machine vnic
VM_Direction(){
    echo "
++++++++++++++++++++++++++++++
|  PACKET CAPTURE DIRECTION  |
++++++++++++++++++++++++++++++"
    while true; do
        echo ""
        echo "Choose the direction you want to capture packets in (1/2)
1. Incoming
2. Outgoing"
        read DIR
        if [ ! $(echo "$DIR" | grep -xE '^[1-2]$') ]; then
            echo ""
            echo "Invalid input. Please choose an option between 1-2."
        else
            break
        fi
    done
}

#Function to input the duration of packet capture
Duration(){
    echo "
++++++++++++++++++++++++++++++
|   PACKET CAPTURE DURATION  |
++++++++++++++++++++++++++++++"
    while true; do
        echo ""
        echo "Choose the duration you want to capture packets for (1/3)
1. 3 minutes
2. 1 hour
3. Continuous (captures packets continuously until terminated)"
        read PCAP_TIME
        if [ ! $(echo "$PCAP_TIME" | grep -xE '^[1-3]$') ]; then
            echo ""
            echo "Invalid input. Please choose an option between 1-3."
        else
            if [ $PCAP_TIME -gt 1 ]; then
                echo "
++++++++++++++++++++++++++++++
|     PACKET CAPTURE SIZE    |
++++++++++++++++++++++++++++++"
                read -p "
Enter the total size you want to limit the packet capture files to. The value must be entered in MB:
" PCAP_SIZE
                PCAP_SIZE_PER_FILE=`awk "BEGIN {print $PCAP_SIZE/20}"`
                PCAP_SIZE_PER_FILE=$(echo $PCAP_SIZE_PER_FILE | awk '{print int($1)}')
                if [ $PCAP_SIZE_PER_FILE -lt 1 ]; then
                    PCAP_SIZE_PER_FILE=1
                fi
                PCAP_COMMAND="${PCAP_COMMAND} -C ${PCAP_SIZE_PER_FILE}"
            fi
            break
        fi
    done
}

#Function to input the location to save the packet capture file(s) in
Directory(){
    echo "
++++++++++++++++++++++++++++++
|  PACKET CAPTURE DIRECTORY  |
++++++++++++++++++++++++++++++"
    while true; do
        echo ""
        echo "Enter the directory to save the packet capture file(s) in:"
        read DIR
        if [ -d "$DIR" ]; then
            PCAP_COMMAND="${PCAP_COMMAND} -s 150 -o $DIR/"$CAP_POINT_TXT"_"$CLIENT"_"$DIR_TXT"_01.pcap"
            break
        elif [ -d "/$DIR" ]; then
            PCAP_COMMAND="${PCAP_COMMAND} -s 150 -o /$DIR/"$CAP_POINT_TXT"_"$CLIENT"_"$DIR_TXT"_01.pcap"
            break
        else
            echo ""
            echo "Invalid input. Please enter a valid directory. Do not enter the filename."
        fi
    done
}

#Main code

#Setting filter flags to ensure a filter can only be applied once
IP_FLAG=False; MAC_FLAG=False; VLAN_FLAG=False; PORT_FLAG=False; PROTO_FLAG=False

#Regular expressions to match valid MAC addresses, IP addresses and port numbers
MAC_REGEX='^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$'
IP_REGEX='^([0-9]{1,2}|(0|1)[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|(0|1)[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|(0|1)[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|(0|1)[0-9]{2}|2[0-4][0-9]|25[0-5])$'
PORT_REGEX='^[0-9]{1,5}$'

#Get the level of packet capture
Level

#Based on the level of packet capture, we start constructing the packet capture command
#Packet capture command is a string variable that is constructed using user inputs
#We then call the Filters() function to allow the user to filter packets as needed
while true; do
    case $CAP_POINT in
        1 ) CAP_POINT_TXT="vmkernel"
            echo ""
            net-stats -l | head -1 
            net-stats -l | grep -i vmk
            echo ""
            echo "Enter the name of a vmkernel interface from the ClientName column in the above list. This is case sensitive:"
            read CLIENT
            if [ "$(net-stats -l | awk '{print $6}' | grep -x $CLIENT | wc -l)" = 0 ]
            then
                echo ""
                echo "Invalid input. Please enter a valid vmkernel interface from the list. Run the script once more if you wish to choose a different capture level."
            else
                PCAP_COMMAND="pktcap-uw --vmk $CLIENT"
                Direction
                case $DIR in
                    1 ) PCAP_COMMAND=" ${PCAP_COMMAND} --capture PortOutput"; DIR_TXT="incoming";;
                    2 ) PCAP_COMMAND=" ${PCAP_COMMAND} --capture PortInput"; DIR_TXT="outgoing";;
                    3 ) PCAP_COMMAND=" ${PCAP_COMMAND} --dir 2"; DIR_TXT="bidirectional";;
                esac
                Filters
                break
                fi
                ;;

        2 ) CAP_POINT_TXT="vnic"
            echo ""
            net-stats -l | head -1 
            net-stats -l | grep -i eth
            echo ""
            echo "Enter the port number of the specific virtual machine network adapter from the PortNum column in the above list:"
            read CLIENT
            if [ "$(net-stats -l | awk '{print $1}' | grep -x $CLIENT | wc -l)" = 0 ]
            then
                echo ""
                echo "Invalid input. Please enter a valid port number from the list. Run the script once more if you wish to choose a different capture level."
            else
                PCAP_COMMAND="pktcap-uw --switchport $CLIENT"
                VM_Direction
                case $DIR in
                    1 ) PCAP_COMMAND=" ${PCAP_COMMAND} --capture VnicRx"; DIR_TXT="incoming";;
                    2 ) PCAP_COMMAND=" ${PCAP_COMMAND} --capture VnicTx"; DIR_TXT="outgoing";;
                esac
                Filters
                break
            fi
            ;;

        3 ) CAP_POINT_TXT="switchport"
            echo ""
            net-stats -l 
            echo ""
            echo "Enter the port number of the specific virtual machine network adapter or vmkernel interface from the PortNum column in the above list:"
            read CLIENT
            if [ "$(net-stats -l | awk '{print $1}' | grep -x $CLIENT | wc -l)" = 0 ]
            then
                echo ""
                echo "Invalid input. Please enter a valid port number from the list. Run the script once more if you wish to choose a different capture level."
            else
                PCAP_COMMAND="pktcap-uw --switchport $CLIENT"
                Direction
                case $DIR in
                    1 ) PCAP_COMMAND=" ${PCAP_COMMAND} --capture PortOutput"; DIR_TXT="incoming";;
                    2 ) PCAP_COMMAND=" ${PCAP_COMMAND} --capture PortInput"; DIR_TXT="outgoing";;
                    3 ) PCAP_COMMAND=" ${PCAP_COMMAND} --dir 2"; DIR_TXT="bidirectional";;
                esac
                CLIENT="$(net-stats -l | grep -i $CLIENT | awk '{print $6}')"
                Filters
                break
            fi
            ;;

        4 ) CAP_POINT_TXT="uplink"
            echo ""
            net-stats -l | head -1 
            net-stats -l | grep vmnic
            echo ""
            echo "Enter the name of a hardware uplink from the ClientName column in the above list. This is case sensitive:"
            read CLIENT
            if [ "$(net-stats -l | awk '{print $6}' | grep -x $CLIENT | wc -l)" = 0 ]
            then
                echo ""
                echo "Invalid input. Please enter a valid hardware uplink from the list. Run the script once more if you wish to choose a different capture level."
            else
                PCAP_COMMAND="pktcap-uw --uplink $CLIENT"
                Direction
                case $DIR in
                    1 ) PCAP_COMMAND=" ${PCAP_COMMAND} --capture UplinkRcvKernel"; DIR_TXT="incoming";;
                    2 ) PCAP_COMMAND=" ${PCAP_COMMAND} --capture UplinkSndKernel"; DIR_TXT="outgoing";;
                    3 ) PCAP_COMMAND=" ${PCAP_COMMAND} --dir 2"; DIR_TXT="bidirectional";;
                esac
                Filters
                break
            fi
            ;;
    esac
done

#We then call Duration() and Directory() to get the duration of packet captures and the location to save the fil(s) in
Duration
Directory

#We confirm that the packet packet capture command has been constructed successfully and print the command for documentation
echo "
THANKS FOR THE INPUTS! CAPTURING PACKETS NOW USING THE COMMAND: "$PCAP_COMMAND"
"

#We then execute the packet capture command depending on the duration chosen by the user
case $PCAP_TIME in
    1 ) for STAMP in 01
        do
            eval $PCAP_COMMAND &
            sleep 180
            pkill pktcap-uw
            echo ""
            echo "PACKETS CAPTURED USING COMMAND: "$PCAP_COMMAND"
            "
            exit
        done	
        ;;
    2 ) for STAMP in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20
        do
            #Incrementing file number to sustain packet sequence across files
            PCAP_COMMAND=${PCAP_COMMAND//_[0-9]*/_$STAMP.pcap}
            eval $PCAP_COMMAND &
            sleep 180
            pkill pktcap-uw
        done
        echo ""
        echo "PACKETS CAPTURED USING COMMAND: "$PCAP_COMMAND"
        "
        exit
        ;;
    3 )	while true
        do
            for STAMP in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20
            do
                PCAP_COMMAND=${PCAP_COMMAND//_[0-9]*/_$STAMP.pcap}
                eval $PCAP_COMMAND &
                sleep 180
                pkill pktcap-uw
            done
        done
        exit
        ;;
esac
exit

#End of script


