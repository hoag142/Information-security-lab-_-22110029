22110029 - Trần Huy Hoàng
# Extra Lab: firewall
# Task (packet filter with iptables):
Network Description
The network consists of two subnets:

- **Subnet 1** (10.9.0.0/24): Contains the outsider (10.9.0.5) and badsite (10.9.0.10).
- **Subnet 2** (172.16.10.0/24): Contains the inner1 (172.16.10.100) and iweb (172.16.10.110).

A router connects these subnets and has the following addresses:

- Subnet 1: 10.9.0.254
- Subnet 2: 172.16.10.10

## A. Setup rules on router to block all access into it except ping.


Exec in router and Clear existing rules and custom chains 
```
  iptables -F

  iptables -X
```

![image](https://github.com/user-attachments/assets/577c6766-69e3-4feb-bd3c-0ebec1cfc2d0)

And add rule with command line :

- ***Allow ICMP (ping) packets*** :
```
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT 

    iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
```

The rules to allow ICMP echo-request and echo-reply packets ensure that ping requests and responses are accepted.

![image](https://github.com/user-attachments/assets/d70b4dad-bf79-41d3-88d2-a1e51cf6e191)



- ***Allow related and established connections*** :
`iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT` :
Allows packets that are part of an existing connection.
![image](https://github.com/user-attachments/assets/93ed6668-2f22-45ca-a57b-b212dd29a5f8)




- ***Allow ICMP traffic in FORWARD chain (for troubleshooting)***:
  ``iptables -I FORWARD 1 -p icmp -j ACCEPT``:
  Inserts a rule at the top of the FORWARD chain to accept ICMP packets for troubleshooting purposes.

  ![image](https://github.com/user-attachments/assets/0583db4c-df50-48b5-93d9-7199f6ccb965)

_**When you check the table, you will see that the rule and chain have been updated**_

![image](https://github.com/user-attachments/assets/16d71a75-cfea-4996-9a42-14f9eaffa0cd)

Exec into each host and ping each other
- **on outsider**

  ![image](https://github.com/hoag142/Information-security-lab-_-22110029/assets/152377486/e7d62351-231a-459f-865e-7cdf3ed678ce)

- **on inner**

![image](https://github.com/hoag142/Information-security-lab-_-22110029/assets/152377486/3f6cbf55-0b2d-4c56-93cb-8674d17662df)

## B. Setup rules on router to prevent computers on subnet 10.9.0.0/24 from accessing the internal web server (iweb).

To block the 10.9.0.0/24 subnet from accessing the internal web server (iweb) at 172.16.10.110, we need to drop packets destined for iweb on ports 80 (HTTP), 443 (HTTPS), and 23 (Telnet).

**Block 10.9.0.0/24 from accessing iweb at 172.16.10.110 (HTTP, HTTPS, and Telnet)**

```
iptables -A FORWARD -s 10.9.0.0/24 -d 172.16.10.110 -p tcp --dport 80 -j DROP 
iptables -A FORWARD -s 10.9.0.0/24 -d 172.16.10.110 -p tcp --dport 443 -j DROP 
iptables -A FORWARD -s 10.9.0.0/24 -d 172.16.10.110 -p tcp --dport 23 -j DROP
```

- The iptables -A FORWARD rules block HTTP (port 80), HTTPS (port 443), and Telnet (port 23) traffic from the 10.9.0.0/24 subnet to the iweb server at 172.16.10.110.

  ![image](https://github.com/user-attachments/assets/da2320b7-eceb-476a-9a51-c105a3dcf699)



**Block ICMP traffic from 10.9.0.0/24 to 172.16.10.0/24**

`iptables -A FORWARD -s 10.9.0.0/24 -d 172.16.10.0/24 -p icmp -j DROP`

- The iptables -A FORWARD rule blocks all ICMP traffic from the 10.9.0.0/24 subnet to the 172.16.10.0/24 subnet, preventing any ping requests between these subnets.

![image](https://github.com/user-attachments/assets/d69bca97-159b-4a5e-93cb-1e136a4c6393)

**Check table again**

![image](https://github.com/user-attachments/assets/eee27f95-7ca9-4c5e-ac59-4d50fd3cc59f)

- When I using command `curl http://172.16.10.110` but not see anything that mean we are on correctly rule.

 ![image](https://github.com/user-attachments/assets/174c5da9-9ae1-472d-8170-12832b2c57c4)



## C. The badsite was found to contain malwares and source of delivering bots. Setup rules on router to stop computers on subnet 172.16.10.0/24 from accessing the badsite.

To block the 172.16.10.0/24 subnet from accessing badsite at 10.9.0.10, we need to drop packets destined for badsite on ports 80 (HTTP), 443 (HTTPS), and 23 (Telnet).

```
# Block 172.16.10.0/24 from accessing badsite at 10.9.0.10 (HTTP, HTTPS, and Telnet)
iptables -A FORWARD -s 172.16.10.0/24 -d 10.9.0.10 -p tcp --dport 80 -j DROP
iptables -A FORWARD -s 172.16.10.0/24 -d 10.9.0.10 -p tcp --dport 443 -j DROP
iptables -A FORWARD -s 172.16.10.0/24 -d 10.9.0.10 -p tcp --dport 23 -j DROP

# Block ICMP traffic from 172.16.10.0/24 to 10.9.0.0/24
iptables -A FORWARD -s 172.16.10.0/24 -d 10.9.0.0/24 -p icmp -j DROP

# Allow ICMP traffic within same subnet (if needed)
iptables -A FORWARD -s 10.9.0.0/24 -d 10.9.0.0/24 -p icmp -j ACCEPT
iptables -A FORWARD -s 172.16.10.0/24 -d 172.16.10.0/24 -p icmp -j ACCEPT

```

***Explanation:***

- The `iptables -A FORWARD` rules block HTTP (port 80), HTTPS (port 443), and Telnet (port 23) traffic from the 172.16.10.0/24 subnet to the badsite server at 10.9.0.10.
- The `iptables -A FORWARD` rule blocks all ICMP traffic from the 172.16.10.0/24 subnet to the 10.9.0.0/24 subnet, preventing any ping requests between these subnets.
- The last two rules ensure that ICMP traffic within the same subnet is allowed, which can be useful for intra-subnet communication and troubleshooting.

**Check on IP table**

![image](https://github.com/user-attachments/assets/aef2fd0f-c467-4384-9641-e9c9e11ce996)


** Ping **
![image](https://github.com/user-attachments/assets/5a39199f-1b1d-472a-9332-881b4f2e36c6)
** Telnet **
![image](https://github.com/user-attachments/assets/1f0541b8-ddac-4b09-ae52-62db9e775f41)


