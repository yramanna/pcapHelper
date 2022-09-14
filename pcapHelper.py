import subprocess
import os
def Filters():
	subprocess.call(["echo","\n++++++++++++++++++++++++++++++\n|   PACKET CAPTURE FILTERS   |\n++++++++++++++++++++++++++++++"])
	while True:
		CHOICE1=input("\nDo you want to further filter this packet capture using any of the below options? (0/1/2/3/4/5)\n0. NO\n1. PROTOCOL\n2. MAC\n3. IP\n4. VLAN\n5. PORT\n")
		if CHOICE1 == 0:
			break
		elif CHOICE1 == 1:
			if PROTO_FLAG == False:
				While True:
					CHOICE2=input("\nPick a protocol to filter for\n0. Return to packet filter menu\n1. ICMP\n2. TCP\n3. UDP\n4. IGMP\n")
                    if choice == 0:
						break
					elif CHOICE2 == 1:
						PROTO="0x01"
						PCAP_COMMAND= PCAP_COMMAND+" --proto "+PROTO
						PROTO_FLAG=True
						break
					elif CHOICE2 == 2:
						PROTO="0x06"
						PCAP_COMMAND= PCAP_COMMAND+" --proto "+PROTO
						PROTO_FLAG=True
						break
					elif CHOICE2 == 3:
						PROTO="0x11"
						PCAP_COMMAND= PCAP_COMMAND+" --proto "+PROTO
						PROTO_FLAG=True
						break
					elif CHOICE2 == 4:
						PROTO="0x02"
						PCAP_COMMAND= PCAP_COMMAND+" --proto "+PROTO
						PROTO_FLAG=True
						break
					else:
						subprocess.call(["echo","Invalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the menu."])
                else
                    subprocess.call(["echo","Protocol filter has already been applied once. Please select another filter or exit this menu."])
		elif CHOICE1 == 2:
			if MAC_FLAG:		
				while true; do
					CHOICE3=input("\nYou can filter the traffic using a MAC address, or using specific source and destination MAC addresses. Please enter your choice (0/1/2/3/4)\n0. Return to packet filter menu\n1. Single MAC address\n2. Specific source MAC address\n3. Specific destination MAC address\n4. Source and destination MAC address\n")
					if CHOICE3 == 0:
						break
					elif CHOICE3 == 1:
						MAC=input("Enter the MAC address: ")
						if not re.match(MAC_REGEX,MAC):
							subprocess.call(["echo","\nInvalid input. Please enter a valid MAC address."
						else:
							MAC_FLAG = 0
							PCAP_COMMAND=PCAP_COMMAND+" --mac "+MAC
							break
					elif CHOICE3 == 2:
						S_MAC=input("Enter the source MAC address: ")
						if not re.match(MAC_REGEX,S_MAC):
							subprocess.call(["echo","\nInvalid input. Please enter a valid MAC address."
						else:
							MAC_FLAG = 0
							PCAP_COMMAND=PCAP_COMMAND+" --srcmac "+S_MAC
							break
					elif CHOICE3 == 3:
						D_MAC=input("Enter the destination MAC address: ")
						if not re.match(MAC_REGEX,D_MAC):
							subprocess.call(["echo","\nInvalid input. Please enter a valid MAC address."
						else:
							MAC_FLAG = 0
							PCAP_COMMAND=PCAP_COMMAND+" --dstmac "+D_MAC
							break
					elif CHOICE3 == 4:
						S_MAC=input("Enter the source MAC address: ")
						if not re.match(MAC_REGEX,S_MAC):
							subprocess.call(["echo","\nInvalid input. Please enter a valid MAC address."
						else:
							D_MAC=input("Enter the destination MAC address: ")
							if not re.match(MAC_REGEX,D_MAC):
								subprocess.call(["echo","\nInvalid input. Please enter a valid MAC address."
							else:
								MAC_FLAG = 0
								PCAP_COMMAND=PCAP_COMMAND+" --srcmac "+S_MAC+" --dstmac "+D_MAC
								break
					else:
						subprocess.call(["echo","Invalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the packet filter menu."])
			else:
				subprocess.call(["echo","MAC filter has already been applied once. Please select another filter or exit this menu."])
		elif CHOICE1 == 3:
			if IP_FLAG: 
				while True:
					CHOICE4=input("\nYou can filter the traffic using an IP address, or using specific source and destination IP addresses. Please enter your choice (0/1/2/3/4)\n0. Return to packet filter menu\n1. Single IP address\n2. Specific source IP address\n3. Specific destination IP address\n4. Source and destination IP address\n")
					if CHOICE4 == 0:
						break
					elif CHOICE4 == 1:
						IP=input("Enter the IP address: ")
						if not re.match(IP_REGEX,IP):
							subprocess.call(["echo","\nInvalid input. Please enter a valid IP address."
						else:
							IP_FLAG = 0
							PCAP_COMMAND=PCAP_COMMAND+" --ip "+IP
							break
					elif CHOICE4 == 2:
						S_IP=input("Enter the source IP address: ")
						if not re.match(IP_REGEX,S_IP):
							subprocess.call(["echo","\nInvalid input. Please enter a valid IP address."
						else:
							IP_FLAG = 0
							PCAP_COMMAND=PCAP_COMMAND+" --srcip "+S_IP
							break
					elif CHOICE4 == 3:
						D_IP=input("Enter the destination IP address: ")
						if not re.match(IP_REGEX,D_IP):
							subprocess.call(["echo","\nInvalid input. Please enter a valid IP address."
						else:
							IP_FLAG = 0
							PCAP_COMMAND=PCAP_COMMAND+" --dstip "+D_IP
							break
					elif CHOICE4 == 4:
						S_IP=input("Enter the source IP address: ")
						if not re.match(IP_REGEX,S_IP):
							subprocess.call(["echo","\nInvalid input. Please enter a valid IP address."
						else:
							D_IP=input("Enter the destination IP address: ")
							if not re.match(IP_REGEX,D_IP):
								subprocess.call(["echo","\nInvalid input. Please enter a valid IP address."
							else:
								IP_FLAG = 0
								PCAP_COMMAND=PCAP_COMMAND+" --srcmac "+S_IP+" --dstmac "+D_IP
								break
					else:
						subprocess.call(["echo","\nInvalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the packet filter menu."])
			else:
				subprocess.call(["echo","IP filter has already been applied once. Please select another filter or exit this menu."])

		elif CHOICE1 == 4:
			if not VLAN_FLAG:
				VLAN_ID = input("Enter the VLAN ID: ")
				if not re.match('[0-9]{1,4}$',VLAN_ID) or VLAN_ID > 4094:
					subprocess.call(["echo","Invalid input. Please enter a valid VLAN ID."])
				else:
					VLAN_FLAG = 1
					PCAP_COMMAND=PCAP_COMMAND+" --vlan "+VLAN_ID
			else:
				subprocess.call(["echo","VLAN filter has already been applied once. Please select another filter or exit this menu."])
		elif CHOICE1 == 5:
			if PORT_FLAG == 0:
				while True
                    PORT_CHOICE = subprocess.call(["echo","\nChoose the type of port you want to filter packets with (0/1/2)\n0. Return to main packet filter menu.\n1. TCP port\n2. UDP port"])
                    if PORT_CHOICE == 0:
						break
					elif PORT_CHOICE == 1:
						while True:
							CHOICE5 = input("You can filter the traffic using a TCP port, or using specific source and destination TCP ports. Please enter your choice (0/1/2/3/4)\n0. Back\n1. Single TCP port\n2. Specific source TCP port\n3. Specific destination TCP port\n4. Source and destination TCP port\n")
                            if CHOICE5 == 0:
								break
							elif CHOICE5 == 1:
								PORT = input("Enter the TCP port: ")
								if not re.match(PORT_REGEX, PORT):
									subprocess.call("echo","Invalid input. Please enter a valid TCP port."])
								else:
									PORT_FLAG= 1
										PCAP_COMMAND=PCAP_COMMAND+" --tcpport "+PORT
										break
							elif CHOICE5 == 2:
								S_PORT = input("Enter the source TCP port: ")
								if not re.match(PORT_REGEX, S_PORT):
									subprocess.call("echo","Invalid input. Please enter a valid TCP port."])
								else:
									PORT_FLAG= 1
									PCAP_COMMAND=PCAP_COMMAND+" --srctcpport "+S_PORT
									break
							elif CHOICE5 == 3:
								D_PORT = input("Enter the destination TCP port: ")
								if not re.match(PORT_REGEX, D_PORT):
									subprocess.call("echo","Invalid input. Please enter a valid TCP port."])
								else:
									PORT_FLAG= 1
									PCAP_COMMAND=PCAP_COMMAND+" --dsttcpport "+D_PORT
									break
							elif CHOICE5 == 4:
								S_PORT=input("Enter the source TCP port: ")
								if not re.match(PORT_REGEX, PORT):
									subprocess.call(["echo","\nInvalid input. Please enter a valid TCP port."
								else:
									D_PORT=input("Enter the destination TCP port: ")
									if not re.match(PORT_REGEX, PORT):
										subprocess.call(["echo","\nInvalid input. Please enter a valid TCP port."
									else:
										PORT_FLAG = 0
										PCAP_COMMAND=PCAP_COMMAND+" --srctcpport "+S_PORT+" --dsttcpport "+D_PORT
										break
							else:
								subprocesss.call(["echo","Invalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the port type menu."])
					elif PORT_CHOICE == 2:
						while True:
							CHOICE5 = input("You can filter the traffic using a UDP port, or using specific source and destination UDP ports. Please enter your choice (0/1/2/3/4)\n0. Back\n1. Single UDP port\n2. Specific source UDP port\n3. Specific destination UDP port\n4. Source and destination UDP port\n")
                            if CHOICE5 == 0:
								break
							elif CHOICE5 == 1:
								PORT = input("Enter the UDP port: ")
								if not re.match(PORT_REGEX, PORT):
									subprocess.call("echo","Invalid input. Please enter a valid UDP port."])
								else:
									PORT_FLAG= 1
										PCAP_COMMAND=PCAP_COMMAND+" --udpport "+PORT
										break
							elif CHOICE5 == 2:
								S_PORT = input("Enter the source UDP port: ")
								if not re.match(PORT_REGEX, S_PORT):
									subprocess.call("echo","Invalid input. Please enter a valid UDP port."])
								else:
									PORT_FLAG= 1
									PCAP_COMMAND=PCAP_COMMAND+" --srcudpport "+S_PORT
									break
							elif CHOICE5 == 3:
								D_PORT = input("Enter the destination UDP port: ")
								if not re.match(PORT_REGEX, D_PORT):
									subprocess.call("echo","Invalid input. Please enter a valid UDP port."])
								else:
									PORT_FLAG= 1
									PCAP_COMMAND=PCAP_COMMAND+" --dstudpport "+D_PORT
									break
							elif CHOICE5 == 4:
								S_PORT=input("Enter the source UDP port: ")
								if not re.match(PORT_REGEX, PORT):
									subprocess.call(["echo","\nInvalid input. Please enter a valid UDP port."
								else:
									D_PORT=input("Enter the destination UDP port: ")
									if not re.match(PORT_REGEX, PORT):
										subprocess.call(["echo","\nInvalid input. Please enter a valid UDP port."
									else:
										PORT_FLAG = 0
										PCAP_COMMAND=PCAP_COMMAND+" --srcudpport "+S_PORT+" --dstudpport "+D_PORT
										break
							else:
								subprocesss.call(["echo","Invalid input. Please choose an option between 1-4 from the above list. Enter 0 to go back to the port type menu."])
							
					else:
						subprocess.call(["echo","Invalid input. Please choose an option between 1-2."])
			else:
				subprocess.call(["echo","Port filter has already been applied once. Please select another filter or exit this menu."])
        else:
			subprocess.call(["echo","Invalid input. Please choose an option between 1-5 from the above list. Enter 0 to exit the packet filter menu."])

#Function to input the level of packet capture
def Level():
	subprocess.call(["echo","\n++++++++++++++++++++++++++++++\n|    PACKET CAPTURE LEVEL    |\n++++++++++++++++++++++++++++++"])
	while True:
		CAP_POINT=input("\nChoose the level you want to capture packets at (1/2/3/4)\n1. vmkernel interface\n2. virtual network adapter\n3. virtual switch port\n4. hardware network adapter/uplink\n")
        if not re.match('^[1-4]$', CAP_POINT):
            subprocess.call(["echo","Invalid input. Please choose an option between 1-4."])
        else:
            break

#Function to input the direction of packet capture
def Direction():
    subprocess.call(["echo","\n++++++++++++++++++++++++++++++\n|  PACKET CAPTURE DIRECTION  |\n++++++++++++++++++++++++++++++"])
    while True:
		VERSION=subprocess.call(["vmware","-vl","|","grep","-oe","[567]\.[057]","|","head -1"])
        if VERSION > 6.6:
			DIR=input("\nChoose the direction you want to capture packets in (1/2/3)\n1. Incoming\n2. Outgoing\n3. Both\n")
            if not re.match('^[1-3]$', DIR):
                subprocess.call(["echo","\nInvalid input. Please choose an option between 1-3."])
            else:
                break
		else:
			DIR=input("\nChoose the direction you want to capture packets in (1/2)\n1. Incoming\n2. Outgoing\n")
            if not re.match('^[1-2]$', DIR):
                subprocess.call(["echo","\nInvalid input. Please choose an option between 1-2."])
            else:
                break

#Function to input the duration of packet capture
def Duration():
    subprocess.call(["echo","\n++++++++++++++++++++++++++++++\n|   PACKET CAPTURE DURATION  |\n++++++++++++++++++++++++++++++"])
    while True:
        TIME_CHOICE=input("\nChoose the duration you want to capture packets for (1/3)\n1. 3 minutes\n2. 1 hour\n3. Continuous (captures packets continuously until script is terminated)\n")
        if not re.match('^[1-3]$', TIME_CHOICE):
            subprocess.call(["echo","Invalid input. Please choose an option between 1-3."])
        elif TIME_CHOICE == 1:
			PCAP_TIME = 1
		elif TIME_CHOICE > 1:
			PCAP_TIME = 20
				subprocess.call(["echo","\n++++++++++++++++++++++++++++++\n|     PACKET CAPTURE SIZE    |\n++++++++++++++++++++++++++++++"])
                SIZE_CHOICE = input("\nDo you wish to limit the total size of all packets captured (1/2)\n1. Yes\n2. No\n")
				if SIZE_CHOICE == 1:
					PCAP_SIZE=input("\nEnter the total size you want to limit the packet capture files to. The value must be entered in MB: ")
					PCAP_SIZE_PER_FILE=max(1,int(PCAP_SIZE)//20)
					PCAP_COMMAND=PCAP_COMMAND+" -C "+PCAP_SIZE_PER_FILE

#Function to input the location to save the packet capture file(s) in
def Directory():
    subprocess.call(["echo","\n++++++++++++++++++++++++++++++\n|  PACKET CAPTURE DIRECTORY  |\n++++++++++++++++++++++++++++++"])
    while True:
        DIR=input("Enter the full path to the directory you want to save the packet capture file(s) in: ")
        if DIR == "":
            DIR=subprocess.call(["pwd"])
            PCAP_COMMAND=PCAP_COMMAND+" -s 150 -o "+DIR+"/"+CAP_POINT_TXT+"_"+CLIENT+"_"+DIR_TXT+"_01.pcap"
            break
		elif os.path.isdir(DIR) or os.path.isdir("/"+DIR):
            PCAP_COMMAND=PCAP_COMMAND+" -s 150 -o "+DIR+"/"+CAP_POINT_TXT+"_"+CLIENT+"_"+DIR_TXT+"_01.pcap"
            break
		else:
            subprocess.call(["echo","Invalid input. Please enter a valid directory. Do not enter the filename."])

#Main code

#Setting filter flags to ensure a filter can only be applied once
IP_FLAG, MAC_FLAG, VLAN_FLAG, PORT_FLAG, PROTO_FLAG=0, 0, 0, 0, 0

#Regular expressions to match valid MAC addresses, IP addresses and port numbers
MAC_REGEX='^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$'
IP_REGEX='^([0-9]{1,2}|(0|1)[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|(0|1)[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|(0|1)[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|(0|1)[0-9]{2}|2[0-4][0-9]|25[0-5])$'
PORT_REGEX='^[0-9]{1,5}$'

#Get the level of packet capture
Level()

#Based on the level of packet capture, we start constructing the packet capture command
#Packet capture command is a string variable that is constructed using user inputs
#We then call the Filters() function to allow the user to filter packets as needed
while True:
    if CAP_POINT == 1:
		CAP_POINT_TXT="vmkernel"
		subprocess.call(["echo","''"])
		subprocess.call([net-stats","-l","|","head","-1"])
		subprocess.call([net-stats","-l","|","grep","-i","vmk"])
		subprocess.call(["echo","''"])
		CLIENT=input("Enter the name of a vmkernel interface from the ClientName column in the above list. This is case sensitive: ")
		if not subprocess.call([net-stats","-l","|","awk","'{print","$6}'","|","grep","-x",CLIENT,"|","wc","-l"]):
			subprocess.call(["echo","Invalid input. Please enter a valid vmkernel interface from the list. Run the script once more if you wish to choose a different capture level."])
		else:
			PCAP_COMMAND="pktcap-uw --vmk "+CLIENT
			Direction()
			if DIR == 1:
				PCAP_COMMAND=PCAP_COMMAND+" --capture PortOutput"
				DIR_TXT="incoming"
			elif DIR == 2:
				PCAP_COMMAND=PCAP_COMMAND+" --capture PortInput"
				DIR_TXT="outgoing"
			elif DIR == 3:
				PCAP_COMMAND=PCAP_COMMAND+" --dir 2"
				DIR_TXT="bidirectional"
			Filters()
			break
    if CAP_POINT == 2:
		CAP_POINT_TXT="vnic"
		subprocess.call(["echo","''"])
		subprocess.call([net-stats","-l","|","head","-1"])
		subprocess.call([net-stats","-l","|","grep","-vE","vmk|vmnic|lag"])
		subprocess.call(["echo","''"])
		CLIENT=input("Enter the port number of the specific virtual machine network adapter from the PortNum column in the above list: ")
		if not subprocess.call([net-stats","-l","|","awk","'{print","$1}'","|","grep","-x",CLIENT,"|","wc","-l"]):
			subprocess.call(["echo","\nInvalid input. Please enter a valid port number from the list. Run the script once more if you wish to choose a different capture level."])
		else:
			PCAP_COMMAND="pktcap-uw --switchport "+CLIENT
			Direction()
			if DIR == 1:
				PCAP_COMMAND=PCAP_COMMAND+" --capture vNicRx"
				DIR_TXT="incoming"
			elif DIR == 2:
				PCAP_COMMAND=PCAP_COMMAND+" --capture vNicTx"
				DIR_TXT="outgoing"
			elif DIR == 3:
				PCAP_COMMAND=PCAP_COMMAND+" --capture VnicRx,vNicTx"
				DIR_TXT="bidirectional"
				Filters()
				break
    if CAP_POINT == 3:
		CAP_POINT_TXT="switchport"
		subprocess.call(["echo","''"])
		subprocess.call([net-stats","-l"])
		subprocess.call(["echo","''"])
		CLIENT=input("Enter the port number of the specific virtual machine network adapter or vmkernel interface from the PortNum column in the above list: ")
		if not subprocess.call([net-stats","-l","|","awk","'{print","$1}'","|","grep","-x",CLIENT,"|","wc","-l"]):
			subprocess.call(["echo","\nInvalid input. Please enter a valid port number from the list. Run the script once more if you wish to choose a different capture level."])
		else:
			PCAP_COMMAND="pktcap-uw --switchport "+CLIENT
			Direction()
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
				Filters()
				break
    if CAP_POINT == 4:
		CAP_POINT_TXT="vmnic"
		subprocess.call(["echo","''"])
		subprocess.call([net-stats","-l","|","head","-1"])
		subprocess.call([net-stats","-l","|","grep","vmnic"])
		subprocess.call(["echo","''"])
		CLIENT=input("Enter the name of a hardware uplink from the ClientName column in the above list. This is case sensitive: ")
		if not subprocess.call([net-stats","-l","|","awk","'{print","$6}'","|","grep","-x",CLIENT,"|","wc","-l"]):
			subprocess.call(["echo","\nInvalid input. Please enter a valid hardware uplink from the list. Run the script once more if you wish to choose a different capture level."])
		else:
			PCAP_COMMAND="pktcap-uw --switchport "+CLIENT
			Direction()
			if DIR == 1:
				PCAP_COMMAND=PCAP_COMMAND+" --capture UplinkRcvKernel"
				DIR_TXT="incoming"
			elif DIR == 2:
				PCAP_COMMAND=PCAP_COMMAND+" --capture UplinkSndKernel"
				DIR_TXT="outgoing"
			elif DIR == 3:
				PCAP_COMMAND=PCAP_COMMAND+" --dir 2"
				DIR_TXT="bidirectional"
				Filters()
				break

#We then call Duration() and Directory() to get the duration of packet captures and the location to save the fil(s) in
Duration()
Directory()

#We confirm that the packet packet capture command has been constructed successfully and print the command for documentation
subprocess.call(["echo","THANKS FOR THE INPUTS! CAPTURING PACKETS NOW USING THE COMMAND: ",PCAP_COMMAND])

#We then execute the packet capture command depending on the duration chosen by the user
if PCAP_TIME == 1:
	for STAMP in range(PCAP_TIME):
		subprocess.call(["eval",PCAP_COMMAND,"&","sleep","180"])
		subprocess.call(["pkill","pktcap-uw"])
		subprocess.call(["echo""\nPACKETS CAPTURED USING COMMAND: ",PCAP_COMMAND])
elif PCAP_TIME == 2:
	for STAMP in range(PCAP_TIME):
		#Incrementing file number to sustain packet sequence across files
		PCAP_COMMAND=PCAP_COMMAND[:-9]+"_"+STAMP+".pcap"
		subprocess.call(["eval",PCAP_COMMAND,"&","sleep","180"])
		subprocess.call(["pkill","pktcap-uw"])
		subprocess.call(["echo""\nPACKETS CAPTURED USING COMMAND: ",PCAP_COMMAND])
elif PCAP_TIME == 3:
	while True:
		for STAMP in range(PCAP_TIME):
			#Incrementing file number to sustain packet sequence across files
			PCAP_COMMAND=PCAP_COMMAND[:-9]+"_"+STAMP+".pcap"
			subprocess.call(["eval",PCAP_COMMAND,"&","sleep","180"])
			subprocess.call(["pkill","pktcap-uw"])
			subprocess.call(["echo""\nPACKETS CAPTURED USING COMMAND: ",PCAP_COMMAND])
		
#End of script

