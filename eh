#!/bin/bash
# OpenVPN road warrior installer for Debian, Ubuntu and CentOS
#curl "https://raw.githubusercontent.com/ssolifd/x/master/openvpn" -o openvpn && bash openvpn

#curl --upload-file ~/ml.ovpn  https://transfer.sh/ml.ovpn

# This script will work on Debian, Ubuntu, CentOS and probably other distros
# of the same families, although no support is offered for them. It isn't
# bulletproof but it will probably work if you simply want to setup a VPN on
# your Debian/Ubuntu/CentOS box. It has been designed to be as unobtrusive and
# universal as possible.


# Detect Debian users running the script with "sh" instead of bash
groupadd nobody
if readlink /proc/$$/exe | grep -qs "dash"; then
	echo "This script needs to be run with bash, not sh"
	exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit 2
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "The TUN device is not available
You need to enable TUN before running this script"
	exit 3
fi

if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS 5 is too old and not supported"
	exit 4
fi
if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL='/etc/rc.d/rc.local'
else
	echo "Looks like you aren't running this installer on Debian, Ubuntu or CentOS"
	exit 5
fi


if [  -s "/usr/sbin/openvpn" ]; then
        echo "openvpn is ok"
else

	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		# Else, the distro is CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl wget ca-certificates -y
	fi
	# An old version of easy-rsa was available by default in some openvpn packages
fi	
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	

	# Enable net.ipv4.ip_forward for the system
	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
	if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then
		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
	fi
	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	
function EasyRSA {
        #wget -O ~/EasyRSA-3.0.1.tgz https://godoq.com/EasyRSA-3.0.1.tgz
wget -O ~/EasyRSA-3.0.1.tgz http://soli-10006287.cos.myqcloud.com/EasyRSA-3.0.1.tgz
        tar xzf ~/EasyRSA-3.0.1.tgz -C ~/
        mv ~/EasyRSA-3.0.1/ /etc/openvpn/
        mv /etc/openvpn/EasyRSA-3.0.1/ /etc/openvpn/easy-rsa/
        chown -R root:root /etc/openvpn/easy-rsa/
        #rm -rf ~/EasyRSA-3.0.1.tgz
        cd /etc/openvpn/easy-rsa/
        # Create the PKI, set up the CA, the DH params and the server + client certificates
        ./easyrsa init-pki
        ./easyrsa --batch build-ca nopass
        ./easyrsa gen-dh
        ./easyrsa build-server-full server nopass
        ./easyrsa build-client-full client nopass
        ./easyrsa gen-crl
        # Move the stuff we need
        cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
        # CRL is read with each client connection, when OpenVPN is dropped to nobody
        chown nobody:nobody /etc/openvpn/crl.pem
        # Generate key for tls-auth
        openvpn --genkey --secret /etc/openvpn/ta.key
}
function server {
GROUPNAME=nobody
echo "port 443
proto tcp
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
        echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf

        echo 'push "dhcp-option DNS 119.29.29.29"' >> /etc/openvpn/server.conf
                echo 'push "dhcp-option DNS 182.254.116.116"' >> /etc/openvpn/server.conf
                echo "keepalive 10 120
cipher AES-128-CBC
comp-lzo
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server.conf
echo "client-cert-not-required" >> /etc/openvpn/server.conf
echo "username-as-common-name" >> /etc/openvpn/server.conf
}
function ml {
rm -rf /etc/openvpn/client-common.txt
IP=$(curl -s ipv4.icanhazip.com)
cat >> /etc/openvpn/client-common.txt<<-EOF
client
dev tun
proto tcp
sndbuf 0
rcvbuf 0
remote $IPADDR 443 tcp
http-proxy $IPADDR 8080
keepalive 10 60  
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-128-CBC
comp-lzo
auth-user-pass
setenv opt block-outside-dns
key-direction 1
verb 3
EOF
 

# Generates the custom ml.ovpn
        cp /etc/openvpn/client-common.txt ~/ml.ovpn
        echo "<ca>" >> ~/ml.ovpn
        cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/ml.ovpn
        echo "</ca>" >> ~/ml.ovpn
        echo "<cert>" >> ~/ml.ovpn
        cat /etc/openvpn/easy-rsa/pki/issued/client.crt >> ~/ml.ovpn
        echo "</cert>" >> ~/ml.ovpn
        echo "<key>" >> ~/ml.ovpn
        cat /etc/openvpn/easy-rsa/pki/private/client.key >> ~/ml.ovpn
        echo "</key>" >> ~/ml.ovpn
        echo "<tls-auth>" >> ~/ml.ovpn
        cat /etc/openvpn/ta.key >> ~/ml.ovpn
        echo "</tls-auth>" >> ~/ml.ovpn

}
function open {
IP=$(curl -s ipv4.icanhazip.com)
#IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
cat >/etc/openvpn/client-common.txt<<-EOF
client
dev tun
proto tcp
sndbuf 0
rcvbuf 0
remote $IPADDR 443 tcp
keepalive 10 60  
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-128-CBC
comp-lzo
setenv opt block-outside-dns
key-direction 1
verb 3
EOF

# Generates the custom open.ovpn
        cp /etc/openvpn/client-common.txt ~/open.ovpn
        echo "<ca>" >> ~/open.ovpn
        cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/open.ovpn
        echo "</ca>" >> ~/open.ovpn
        echo "<cert>" >> ~/open.ovpn
        cat /etc/openvpn/easy-rsa/pki/issued/client.crt >> ~/open.ovpn
        echo "</cert>" >> ~/open.ovpn
        echo "<key>" >> ~/open.ovpn
        cat /etc/openvpn/easy-rsa/pki/private/client.key >> ~/open.ovpn
        echo "</key>" >> ~/open.ovpn
        echo "<tls-auth>" >> ~/open.ovpn
        cat /etc/openvpn/ta.key >> ~/open.ovpn
        echo "</tls-auth>" >> ~/open.ovpn

}
function squid {
apt-get -y install squid
cat > /etc/squid/squid.conf <<-END
acl manager proto cache_object
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl localnet src 192.168.99.0/24
acl checker src 203.92.128.158
acl SSL_ports port 443
acl Safe_ports port 80		# http
acl Safe_ports port 21		# ftp
acl Safe_ports port 443		# https
acl Safe_ports port 70		# gopher
acl Safe_ports port 210		# wais
acl Safe_ports port 1025-65535	# unregistered ports
acl Safe_ports port 280		# http-mgmt
acl Safe_ports port 488		# gss-http
acl Safe_ports port 591		# filemaker
acl Safe_ports port 777		# multiling http
acl CONNECT method CONNECT
acl HEAD method HEAD
acl terlarang url_regex -i "/etc/squid3/terlarang.txt"
acl DOMAIN dstdomain musiccssg.digi.com.my facebook.com p1.com.my id.maxis.com.my dealernet.maxis.com.my pluzmusic.digi.com.my mini5-5.opera-mini.net weixin.qq.com v1.hotlink.com.my torrent.bitchdeezer.info era.fm p85.bitchdeezer.info p1.bitchdeezer.info p2.bitchdeezer.info p3.bitchdeezer.info p4.bitchdeezer.info p26.bitchdeezer.info n1.bitchdeezer.info n2.bitchdeezer.info n3.bitchdeezer.info 
http_access deny terlarang
acl localnet src 192.168.0.0/16
acl localnet src 172.16.0.0/12
acl localnet src 10.0.0.0/8
acl deny_sony dstdomain "/etc/squid/sony-domains.txt"
acl allowed_hosts dstdomain  .youtube.com .ytimg.com .doubleclick.net .googlevideo.com 
acl allowed_hosts dstdomain .twitter.com
acl allowed_hosts dstdomain .google.com
acl allowed_hosts dstdomain .facebook.com
acl allowed_hosts dstdomain .viber.com
acl allowed_hosts dstdomain .digi.com.my
acl allowed_hosts dstdomain .maxis.com.my
acl allowed_hosts dstdomain .viber.com
acl allowed_hosts dstdomain .softether.net
acl allowed_hosts dstdomain .gmail.com .flickr.com .yimg.com .digg.com .fbcdn.net .doubleclick.net .googlevideo.com .amazonaws.com .1e100.net
acl allowed_hosts dstdomain .cmru.info .team28devs.com
acl allowed_ip dst 127.0.0.0/8
acl allowed_ip dst xxxxxxxxx
acl CONNECT method CONNECT
acl all src 0.0.0.0/0
http_access allow all
http_access allow localhost manager
http_access allow localhost
http_access allow localnet
http_access allow localnet CONNECT
http_access allow all CONNECT allowed_hosts
http_access allow all allowed_hosts
http_access allow all allowed_ip
http_access allow all CONNECT allowed_ip
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access deny manager
http_access deny all
http_port 8888
http_port 8080
http_port 8000
http_port 80
http_port 3128
## header list ( DENY all -> ALLOW only listed )
via off
forwarded_for off
request_header_access Allow allow all 
request_header_access Authorization allow all 
request_header_access WWW-Authenticate allow all 
request_header_access Proxy-Authorization allow all 
request_header_access Proxy-Authenticate allow all 
request_header_access Cache-Control allow all 
request_header_access Content-Encoding allow all 
request_header_access Content-Length allow all 
request_header_access Content-Type allow all 
request_header_access Date allow all 
request_header_access Expires allow all 
request_header_access Host allow all 
request_header_access If-Modified-Since allow all 
request_header_access Last-Modified allow all 
request_header_access Location allow all 
request_header_access Pragma allow all 
request_header_access Accept allow all 
request_header_access Accept-Charset allow all 
request_header_access Accept-Encoding allow all 
request_header_access Accept-Language allow all 
request_header_access Content-Language allow all 
request_header_access Mime-Version allow all 
request_header_access Retry-After allow all 
request_header_access Title allow all 
request_header_access Connection allow all 
request_header_access Proxy-Connection allow all 
request_header_access User-Agent allow all 
request_header_access Cookie allow all 
request_header_access All deny all
visible_hostname musiccssg.digi.com.my
cache_mgr tonggakod@gmail.com
cache_effective_user proxy
cache_mem 16 MB
maximum_object_size 10240 KB
minimum_object_size 8 KB
maximum_object_size_in_memory 16 KB
cache_dir ufs /var/spool/squid 10000 16 256
END
sed -i $MYIP2 /etc/squid/squid.conf;
service squid restart
}
function set {
systemctl start openvpn@server.service
systemctl -f enable openvpn@server.service
systemctl status openvpn@server.service
yum install iptables-services -y
systemctl mask firewalld
systemctl enable iptables
systemctl stop firewalld
systemctl start iptables
iptables --flush
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
iptables-save > /etc/sysconfig/iptables
}
if [  -s "/etc/openvpn/easy-rsa/easyrsa" ]; then
        echo "EasyRSA is ok"
else
EasyRSA
fi
if [  -s "/etc/openvpn/server.conf" ]; then
        echo "server.conf is ok"
else
server
fi
if [  -s "/usr/sbin/squid" ]; then
        echo "squid is ok"
else
squid
fi
ml
open

