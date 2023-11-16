

# Studying attacks on the TCP/IP Protocol Stack


# Introduction:

 The objective of this project is to explore and discover the different vulnerabilities on the TCP/IP protocol stack and to conduct different attacks using these vulnerabilities.
 The TCP / IP protocols only transmits packets (in clear) from one station to another. This protocol therefore suffers from certain shortcomings in terms of security:

• Packets can be intercepted to read their content (sniffing),

• There is no authentication, we can claim to have an IP number that is not ours (IP spoofing),

• A TCP connection can be intercepted and manipulated by an attacker located on the path of this connection (TCP hijacking),

• TCP protocol implementations are likely to be subject to denial of service attacks (SYN flooding, Land attack, ping of death ...).

# Materials and Methods:

The project demonstration is best realised with at least 3 machines in most cases (one attacker, one victim and one observer). I used VMware Workstation as it is the virtualisation software I prefer and with which I have the most experience. Ubuntu 12.04 is running on all the virtual machines, they are all reachable, on the same network (192.168.211.0) and have access to Internet. Different tools are needed such as Wireshark for the traffic and packet analysis, Ettercap to launch attacks, Hping3 and Netwox which will mainly be used to create and send different types of packet in the network.

<img src="https://i.imgur.com/lyOeDnp.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

# Private network set up:

A first virtual machine is opened from an existing virtual disk with Ubuntu 12.04 already installed as well as Wireshark and Netwox, only Hping3 and Ettercap need to be installed. The network setting is NAT so the virtual machine can have access to the Internet from the host machine.

<img src="https://i.imgur.com/lYnWGDw.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Then I created two clones from the initial virtual machine, so they all have the same settings and tools installed.

<img src="https://i.imgur.com/HiQB4tJ.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

In total 3 virtual machines are used, all within the same network and able to ping each other.

Attacker:

<img src="https://i.imgur.com/tEsSw9I.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Victim:

<img src="https://i.imgur.com/4Hd8mAk.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Observer:

<img src="https://i.imgur.com/IxAD7H7.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Installation of Hping3 on the attacker:

<img src="https://i.imgur.com/Ooc9opY.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

# Steps to carry out the experiment:

The project objective is to study attacks on the TCP/IP stack, to achieve this objective I am going to study 5 different attacks, namely ARP Cache poisoning, SYN flooding attack, TCP RST attack on SSH connection, TCP RST attack on a video streaming application and ICMP redirect attack.

## ARP Cache Poisoning:

This technique aims to modify the routing at level 2 and makes it possible to be an interceptor ( "Man In The Middle" attack) on a local network. The ARP protocol is the protocol ensuring the correspondence on a local network between the level 2 addresses (MAC addresses) and the level 3 addresses (IP addresses). By modifying the associations, it is possible to make a machine believe that the IP address of its correspondent is in fact at the MAC address of a pirate machine.

The ARP protocol (RFC 826) was created without taking into account aspects of machine authentication, so that any machine on a network is able to advertise itself as the owner of an IP address.

The use of an insecure protocol, coupled with poor implementations in operating systems, means that to this day almost all systems are vulnerable to ARP cache poisoning.

Although the RFC defines the format of messages, it is possible to send them in multiple forms. Thus, an ARP frame can be encoded in 8 different ways (broadcast or unicast, whois or reply, gratuitous or not). Depending on the result you want to obtain (creation of a table entry, update), it is possible to use or combine these messages.

Attacks implementing the ARP protocol are numerous and range from eavesdropping on a switched network to denial of service, including spoofing and attacking the interceptor.

Simulation of the attack:

First, we will need to use arpspoof and Ettercap on the attacker machine, so we are going to install them

<img src="https://i.imgur.com/rWeNRaa.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

<img src="https://i.imgur.com/1PxmyMw.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Then we make sure we can access the designed website with the victim machine

<img src="https://i.imgur.com/ANjwXvR.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

We will use the arpspoof command on the attacker machine. This is going to rearrange the arp table so we can no longer ping the website on the victim machine.

<img src="https://i.imgur.com/RZyCH1q.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Then we start Ettercap on the attacker machine to start the attack.

First, we select the network interface

<img src="https://i.imgur.com/2FTrvKt.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Scan for hosts in the network

<img src="https://i.imgur.com/xBgcYPX.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

We can see the host list obtained

<img src="https://i.imgur.com/jjvIhAU.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Then we assign the targets, the victim machine (192.168.211.129) will be the main target and the router (host machine, 192.168.211.2) will be the second target. And finally, we use the Man in the Middle functionality to arpspoof. 
<img src="https://i.imgur.com/8oTxbLV.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

## SYN Flooding:

SYN flooding is a network saturation attack (Denial Of Service) exploiting the mechanism of the three-way handshake of the TCP protocol. The three-step handshake mechanism is the way in which any "reliable" connection to the internet (using the TCP protocol) is carried out. When a client establishes a connection to a server, the client sends a SYN request, the server responds with a SYN/ACK packet and finally the client validates the connection with an iACK packet (acknowledgment, which means agreement or thank you).

A TCP connection can only be established when these 3 steps have been completed. The SYN attack involves sending a large number of SYN requests to a host with a non-existent or invalid source IP address. Thus, it is impossible for the target machine to receive an ACK packet.

Machines vulnerable to SYN attacks queue iup the connections opened in this way, in a data structure, and wait to receive an ACK packet. There is a timeout mechanism that allows packets to be dropped after a certain period of time. However, with a very large number of SYN packets, if the resources used by the target machine to store the pending requests are exhausted, it risks entering an unstable state which could lead to a crash or a restart.

<img src="https://i.imgur.com/IhaibY6.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Simulation of the attack:

To simulate a SYN Flooding attack we are going to use Hping3, the following command will start a SYN flood attack on the victim (192.168.211.129) from the attacker (192.168.211.128). It is sending 10000 packets (-c 10000) at a size of 100 bytes (-d 100), the SYN flag is enabled (-S) and the TCP window size is 64 (-w64). The flood flag is used to send packets really quickly and the rand source flag allows the attacker to be anonymous as it generates spoofed IP addresses.

<img src="https://i.imgur.com/0KH5Lge.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Detection of the attack:

To detect the SYN Flood attack we are going to use Wireshark on the victim machine. We will filter the capture to only show SYN packets without acknowledgement first to see the number of packets sent.

<img src="https://i.imgur.com/HB40ou3.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

We can see that there is a large number of SYN packets within a short period of time, we can also see that all the source IP addresses are different, with a packet length of 100 bytes, a tcp window size of 64 and all going to the http port 80.

Now if we compare the number of SYN packets to the number of SYN/ACK packets we can see that there is way more SYN packets, showing that the SYN Flooding attack was successful.

<img src="https://i.imgur.com/zEgYXBK.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

## TCP RST Attack on SSH connection:

A flaw in the TCP/IP stack makes it possible to terminate an active TCP connection, provided you know the port used by this connection.

It consists in generating packets which generate a reset, allowing the attacker to cut off the victim's connection, remotely. Connections such as FTP, telnet, SSH, ...) are then the potential targets of this attack.

The technique is to send a PSH ACK packet to the victim, which returns an ACK packet containing the sequence number of the established TCP connection. Then you only need to send an RST packet with this sequence number to the victim to stop the connection.

Simulation of the attack:

To simulate this attack, we are going to need an SSH connection between two systems (Attacker and Victim) connected on the same network. We will use Hping3 to simulate the attack and Wireshark to monitor it.

First, we need to set up the SSH connection, using the username, IP address and password of the second machine:

<img src="https://i.imgur.com/d60Ulzc.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

I used a few simple commands and created a test folder to confirm that the connection works.

<img src="https://i.imgur.com/ugWXZa0.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Then we start a capture on Wireshark and send a few commands through the SSH connection to see the SSH packets on Wireshark.

We also apply a filter to show only the packets between the attacker and victim's IP addresses

<img src="https://i.imgur.com/5asCM3k.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Now, we are going to use the details from Wireshark in Hping3 to create a spoof TCP reset packet to terminate the TCP connection between the two machines.

The command syntax is the following, in a new terminal window, we start with the destination IP address, then -p option, the port number, which is 22, -s and the source port number (displayed on Wireshark) which is 33051, -R option (reset flag), -A option (acknowledgement flag), -M and then the next sequence number , -L and the acknowledgement number.

<img src="https://i.imgur.com/NMtbB3Y.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Detection of the attack:

After the command has been executed successfully, we can see on the other terminal window with the SSH connection that when we try executing commands, we receive a broken pipe error message which shows that the TCP connection has been terminated

<img src="https://i.imgur.com/tLRbklB.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

We can also see on Wireshark that a Reset packet has been sent from the machine, we can conclude that the TCP RST attack has been executed successfully.

<img src="https://i.imgur.com/oiuhCk0.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

## TCP RST Attack on video streaming application:

This attack is similar to the previous attack, only with the difference in the sequence numbers as in this case, the sequence numbers increase very fast unlike in the SSH attack as we are not typing anything in the terminal.

Simulation of the attack:

We will open Wireshark on the attacker to track the packets.

On the victim machine we will start watching a video, we can see that it is being loaded and it is playing correctly. On Wireshark, we can see that the packets are completely normal.

<img src="https://i.imgur.com/pZ6CXxL.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Then, on the attacker machine we will the command netwox 78 which resets TCP packets.

The -d option is to indicate on which device to sniff, eth0 in this case.

The -f option is to indicate the filter on the sniff, so it only captures packets from the port 443 here.

The -s option with the "raw" argument means that the address spoofing will be made at the IPv4/IPv6 level.

And then we give the victim IP address.

Detection of the attack:

We can see that after we start the attack, the video stops being loaded so after a few seconds the video actually stops. We can see many TCP reset packets being sent on Wireshark.

<img src="https://i.imgur.com/em3dQfm.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

After that, we stop the command which was still running and after a few second we can see that there is a significant decrease in the number of TCP reset packets sent and that the video starts loading and playing again.

<img src="https://i.imgur.com/AEqW1ON.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

## ICMP Redirect Attack:

The ICMP protocol has a fundamental role in the TCP/IP stack. The IP protocol does not offer any guarantee that a datagram has arrived correctly and several problems can arise that prevent its correct functioning. It is the role of the ICMP protocol to provide a mechanism for " error reporting " (not correction). As a result, the ICMP protocol is inseparable and essential for any implementation of the IP protocol.

A datagram can be rejected if the port number does not exist. Many other problems can arise during the routing of an IP datagram: if a machine is disconnected (temporarily or permanently) the router cannot send it the datagram, if the lifetime of a packet is exhausted the router cannot deliver it, if a router is congested the datagrams can no longer progress. If there is a problem, the ICMP protocol does not correct the error but sends a message to the sender who must in turn notify the application. Indeed, the only information the router has is the source address (source IP address in the datagram in question), but if the problem comes from an intermediate router, for example, there is no way to fix it.

The role of ICMP is to report information such as errors to a host. Several attacks use an ICMP message, for example, ICMP Redirect attacks which consist in sending fake messages that redirect traffic destined for a trusted domain.

Simulation of the attack:

Modify the sysctl.conf file on the victim machine

<img src="https://i.imgur.com/1b2ilag.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Change these values to 1

<img src="https://i.imgur.com/CR3GYZY.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

And then refresh the file so the changes are implemented

<img src="https://i.imgur.com/x4sjdzF.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

On the observer machine we need to start capturing packets with Wireshark

<img src="https://i.imgur.com/MwEEWVJ.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Then the victim needs to ping the observer

<img src="https://i.imgur.com/jP8nb1g.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

On the observer we can see on Wireshark the ICMP requests sent between the victim and the observer machine

<img src="https://i.imgur.com/M4vyRq2.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

On the attacker machine we will use the netwox 86 command to send ICMP Redirect packets

We indicate the device on which to sniff, then the filter applied so that only certain packets are captured. Then we indicate the new gateway to use, how the IP will be spoofed, the ICMP code and finally the source IP address.

<img src="https://i.imgur.com/eVhj5eC.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Then the victim sends another ping to the observer

<img src="https://i.imgur.com/iNRIOS3.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Detection of the attack:

On the observer we can see on Wireshark the redirected ICMP packets

<img src="https://i.imgur.com/KSQ9Hzu.png[/img]" height="80%" width="80%" alt="Disk Sanitization Steps"/>

# Conclusion

I can say that I have a better knowledge of how TCP/IP protocols works and also what are some of their vulnerabilities. In total 5 different attacks on the TCP/IP protocol stack have been experimented, ARP Cache Poisoning, SYN Flooding, ICMP Redirect attack and 2 TCP Reset attacks, one on SSH connection and another one on Video Streaming Application. Doing a complete project from start to finish was a really interesting and useful process for my professional growth.

