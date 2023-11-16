

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

![](RackMultipart20231116-1-uj3yyu_html_5fbd926508f2e924.png)

# Private network set up:

A first virtual machine is opened from an existing virtual disk with Ubuntu 12.04 already installed as well as Wireshark and Netwox, only Hping3 and Ettercap need to be installed. The network setting is NAT so the virtual machine can have access to the Internet from the host machine.

![](RackMultipart20231116-1-uj3yyu_html_5b6520fdac348417.png)

Then I created two clones from the initial virtual machine, so they all have the same settings and tools installed.

![](RackMultipart20231116-1-uj3yyu_html_2fbb68374bce01e8.png)

In total 3 virtual machines are used, all within the same network and able to ping each other.

Attacker:

![](RackMultipart20231116-1-uj3yyu_html_b613944be7407b17.png)

Victim:

![](RackMultipart20231116-1-uj3yyu_html_1300f5146d74a35.png)

Observer:

![](RackMultipart20231116-1-uj3yyu_html_31b58aca57c9bfde.png)

Installation of Hping3 on the attacker:

![](RackMultipart20231116-1-uj3yyu_html_2fb7bbb71cb67f17.png)

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

![](RackMultipart20231116-1-uj3yyu_html_422a8c18327658d7.png)

![](RackMultipart20231116-1-uj3yyu_html_412e5dcde2a92f1.png)

Then we make sure we can access the designed website with the victim machine

![](RackMultipart20231116-1-uj3yyu_html_ffb964d980862d30.png)

We will use the arpspoof command on the attacker machine. This is going to rearrange the arp table so we can no longer ping the website on the victim machine.

![](RackMultipart20231116-1-uj3yyu_html_5c6b652f1b2cee73.png)

Then we start Ettercap on the attacker machine to start the attack.

First, we select the network interface

![](RackMultipart20231116-1-uj3yyu_html_88da6fd05e2abbad.png)

Scan for hosts in the network

![](RackMultipart20231116-1-uj3yyu_html_4940c9164501cd82.png)

We can see the host list obtained

![](RackMultipart20231116-1-uj3yyu_html_6de89815a55d1fd7.png)

Then we assign the targets, the victim machine (192.168.211.129) will be the main target and the router (host machine, 192.168.211.2) will be the second target. And finally, we use the Man in the Middle functionality to arpspoof. ![](RackMultipart20231116-1-uj3yyu_html_80128b83c7561a4b.png)

## SYN Flooding:

SYN flooding is a network saturation attack (Denial Of Service) exploiting the mechanism of the three-way handshake of the TCP protocol. The three-step handshake mechanism is the way in which any "reliable" connection to the internet (using the TCP protocol) is carried out. When a client establishes a connection to a server, the client sends a SYN request, the server responds with a SYN/ACK packet and finally the client validates the connection with an iACK packet (acknowledgment, which means agreement or thank you).

A TCP connection can only be established when these 3 steps have been completed. The SYN attack involves sending a large number of SYN requests to a host with a non-existent or invalid source IP address. Thus, it is impossible for the target machine to receive an ACK packet.

Machines vulnerable to SYN attacks queue iup the connections opened in this way, in a data structure, and wait to receive an ACK packet. There is a timeout mechanism that allows packets to be dropped after a certain period of time. However, with a very large number of SYN packets, if the resources used by the target machine to store the pending requests are exhausted, it risks entering an unstable state which could lead to a crash or a restart.

![](RackMultipart20231116-1-uj3yyu_html_ea0c27ac4bfc37e.png)

Simulation of the attack:

To simulate a SYN Flooding attack we are going to use Hping3, the following command will start a SYN flood attack on the victim (192.168.211.129) from the attacker (192.168.211.128). It is sending 10000 packets (-c 10000) at a size of 100 bytes (-d 100), the SYN flag is enabled (-S) and the TCP window size is 64 (-w64). The flood flag is used to send packets really quickly and the rand source flag allows the attacker to be anonymous as it generates spoofed IP addresses.

![](RackMultipart20231116-1-uj3yyu_html_b8328ff0d51bb408.png)

Detection of the attack:

To detect the SYN Flood attack we are going to use Wireshark on the victim machine. We will filter the capture to only show SYN packets without acknowledgement first to see the number of packets sent.

![](RackMultipart20231116-1-uj3yyu_html_6852be1bf3d16a85.png)

We can see that there is a large number of SYN packets within a short period of time, we can also see that all the source IP addresses are different, with a packet length of 100 bytes, a tcp window size of 64 and all going to the http port 80.

Now if we compare the number of SYN packets to the number of SYN/ACK packets we can see that there is way more SYN packets, showing that the SYN Flooding attack was successful.

![](RackMultipart20231116-1-uj3yyu_html_d13ad2c6e5026b57.png)

## TCP RST Attack on SSH connection:

A flaw in the TCP/IP stack makes it possible to terminate an active TCP connection, provided you know the port used by this connection.

It consists in generating packets which generate a reset, allowing the attacker to cut off the victim's connection, remotely. Connections such as FTP, telnet, SSH, ...) are then the potential targets of this attack.

The technique is to send a PSH ACK packet to the victim, which returns an ACK packet containing the sequence number of the established TCP connection. Then you only need to send an RST packet with this sequence number to the victim to stop the connection (Watson 2004).

Simulation of the attack:

To simulate this attack, we are going to need an SSH connection between two systems (Attacker and Victim) connected on the same network. We will use Hping3 to simulate the attack and Wireshark to monitor it.

First, we need to set up the SSH connection, using the username, IP address and password of the second machine:

![](RackMultipart20231116-1-uj3yyu_html_2afd861e78d378d2.png)

I used a few simple commands and created a test folder to confirm that the connection works.

![](RackMultipart20231116-1-uj3yyu_html_9bab54e7040f6024.png)

Then we start a capture on Wireshark and send a few commands through the SSH connection to see the SSH packets on Wireshark.

We also apply a filter to show only the packets between the attacker and victim's IP addresses

![](RackMultipart20231116-1-uj3yyu_html_d64fa36576877706.png)

Now, we are going to use the details from Wireshark in Hping3 to create a spoof TCP reset packet to terminate the TCP connection between the two machines.

The command syntax is the following, in a new terminal window, we start with the destination IP address, then -p option, the port number, which is 22, -s and the source port number (displayed on Wireshark) which is 33051, -R option (reset flag), -A option (acknowledgement flag), -M and then the next sequence number , -L and the acknowledgement number.

![](RackMultipart20231116-1-uj3yyu_html_1163a260f95dabbb.png)

Detection of the attack:

After the command has been executed successfully, we can see on the other terminal window with the SSH connection that when we try executing commands, we receive a broken pipe error message which shows that the TCP connection has been terminated

![](RackMultipart20231116-1-uj3yyu_html_3eb58e871f34813a.png)

We can also see on Wireshark that a Reset packet has been sent from the machine, we can conclude that the TCP RST attack has been executed successfully.

![](RackMultipart20231116-1-uj3yyu_html_d44928be80ce4b5.png)

## TCP RST Attack on video streaming application:

This attack is similar to the previous attack, only with the difference in the sequence numbers as in this case, the sequence numbers increase very fast unlike in the SSH attack as we are not typing anything in the terminal.

Simulation of the attack:

We will open Wireshark on the attacker to track the packets.

On the victim machine we will start watching a video, we can see that it is being loaded and it is playing correctly. On Wireshark, we can see that the packets are completely normal.

![](RackMultipart20231116-1-uj3yyu_html_a61ed34ed32263b8.png)

Then, on the attacker machine we will the command netwox 78 which resets TCP packets.

The -d option is to indicate on which device to sniff, eth0 in this case.

The -f option is to indicate the filter on the sniff, so it only captures packets from the port 443 here.

The -s option with the "raw" argument means that the address spoofing will be made at the IPv4/IPv6 level.

And then we give the victim IP address.

Detection of the attack:

We can see that after we start the attack, the video stops being loaded so after a few seconds the video actually stops. We can see many TCP reset packets being sent on Wireshark.

![](RackMultipart20231116-1-uj3yyu_html_fa3a5b89bc2dc4fd.png)

After that, we stop the command which was still running and after a few second we can see that there is a significant decrease in the number of TCP reset packets sent and that the video starts loading and playing again.

![](RackMultipart20231116-1-uj3yyu_html_d65948ac45846480.png)

## ICMP Redirect Attack:

The ICMP protocol has a fundamental role in the TCP/IP stack. The IP protocol does not offer any guarantee that a datagram has arrived correctly and several problems can arise that prevent its correct functioning. It is the role of the ICMP protocol to provide a mechanism for " error reporting " (not correction). As a result, the ICMP protocol is inseparable and essential for any implementation of the IP protocol.

A datagram can be rejected if the port number does not exist. Many other problems can arise during the routing of an IP datagram: if a machine is disconnected (temporarily or permanently) the router cannot send it the datagram, if the lifetime of a packet is exhausted the router cannot deliver it, if a router is congested the datagrams can no longer progress. If there is a problem, the ICMP protocol does not correct the error but sends a message to the sender who must in turn notify the application. Indeed, the only information the router has is the source address (source IP address in the datagram in question), but if the problem comes from an intermediate router, for example, there is no way to fix it.

The role of ICMP is to report information such as errors to a host. Several attacks use an ICMP message, for example, ICMP Redirect attacks which consist in sending fake messages that redirect traffic destined for a trusted domain.

Simulation of the attack:

Modify the sysctl.conf file on the victim machine

![](RackMultipart20231116-1-uj3yyu_html_c32dc54fe3314767.png)

Change these values to 1

![](RackMultipart20231116-1-uj3yyu_html_3fcf877f2e0bcdf8.png)

And then refresh the file so the changes are implemented

![](RackMultipart20231116-1-uj3yyu_html_a2d639ceb6924392.png)

On the observer machine we need to start capturing packets with Wireshark

![](RackMultipart20231116-1-uj3yyu_html_fa4543a3260cc7e7.png)

Then the victim needs to ping the observer

![](RackMultipart20231116-1-uj3yyu_html_6810a0aa3e70b42.png)

On the observer we can see on Wireshark the ICMP requests sent between the victim and the observer machine

![](RackMultipart20231116-1-uj3yyu_html_96e8dbf6efc92a21.png)

On the attacker machine we will use the netwox 86 command to send ICMP Redirect packets

We indicate the device on which to sniff, then the filter applied so that only certain packets are captured. Then we indicate the new gateway to use, how the IP will be spoofed, the ICMP code and finally the source IP address.

![](RackMultipart20231116-1-uj3yyu_html_4b7a68160f1fd257.png)

Then the victim sends another ping to the observer

![](RackMultipart20231116-1-uj3yyu_html_75592e9283ce11a7.png)

Detection of the attack:

On the observer we can see on Wireshark the redirected ICMP packets

![](RackMultipart20231116-1-uj3yyu_html_f67322aa055716b4.png)

# Conclusion

I can say that I have a better knowledge of how TCP/IP protocols works and also what are some of their vulnerabilities. In total 5 different attacks on the TCP/IP protocol stack have been experimented, ARP Cache Poisoning, SYN Flooding, ICMP Redirect attack and 2 TCP Reset attacks, one on SSH connection and another one on Video Streaming Application. Doing a complete project from start to finish was a really interesting and useful process for my professional growth.

