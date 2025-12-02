# 2025-12-01 11:04:40 by RouterOS 7.20.5
# software id = QBAD-PIH8
#
# model = RBwAPG-5HacD2HnD
# serial number = HE108SF0CWG
/interface bridge
add auto-mac=yes comment=defconf name=bridge \
    port-cost-mode=short
/interface list
add comment=defconf name=WAN
add comment=defconf name=LAN
/interface lte apn
set [ find default=yes ] ip-type=ipv4 use-network-apn=no
/interface wireless security-profiles
set [ find default=yes ] supplicant-identity=MikroTik
add authentication-types=wpa-psk,wpa2-psk mode=dynamic-keys name=ZIELAP \
    supplicant-identity=MikroTik wpa-pre-shared-key=6572747975 \
    wpa2-pre-shared-key=6572747975
/interface wireless
set [ find default-name=wlan1 ] antenna-gain=0 band=2ghz-onlyg country=\
    "united states" disabled=no distance=indoors installation=outdoor mode=\
    ap-bridge security-profile=ZIELAP ssid=ZIEL:AP wireless-protocol=802.11 \
    wps-mode=disabled
/interface wireless
set [ find default-name=wlan2 ] band=5ghz-a/n/ac channel-width=\
    20/40/80mhz-XXXX disabled=no distance=indoors frequency=auto \
    installation=outdoor mode=ap-bridge ssid=ZIEL:INVITADOS security-profile=ZIELAP\
    wireless-protocol=802.11 wps-mode=disabled
/ip pool
add name=default-dhcp ranges=192.168.88.10-192.168.88.254
add name=dhcp_pool1 ranges=172.17.2.200-172.17.2.254
/ip dhcp-server
add address-pool=dhcp_pool1 interface=bridge name=dhcp1
/interface bridge port
add bridge=bridge comment=defconf ingress-filtering=no interface=wlan1 \
    internal-path-cost=10 path-cost=10
add bridge=bridge comment=defconf ingress-filtering=no interface=wlan2 \
    internal-path-cost=10 path-cost=10
add bridge=bridge interface=ether1
/ip firewall connection tracking
set udp-timeout=10s
/ip neighbor discovery-settings
set discover-interface-list=LAN
/ip settings
set max-neighbor-entries=8192
/ipv6 settings
set disable-ipv6=yes max-neighbor-entries=8192
/interface list member
add comment=defconf interface=bridge list=LAN
add comment=defconf interface=ether2 list=WAN
/ip address
add address=192.168.88.1/24 comment=defconf interface=bridge network=\
    192.168.88.0
add address=172.17.2.1/24 interface=bridge network=172.17.2.0
/ip dhcp-client
# Interface not active
add comment=defconf default-route-tables=main interface=ether2
/ip dhcp-server network
add address=172.17.2.0/24 dns-server=1.1.1.1 gateway=172.17.2.1
/ip dns
set allow-remote-requests=yes
/ip dns static
add address=192.168.88.1 comment=defconf name=router.lan type=A
/ip firewall filter
add action=accept chain=input comment=\
    "defconf: accept established,related,untracked" connection-state=\
    established,related,untracked
add action=drop chain=input comment="defconf: drop invalid" connection-state=\
    invalid
add action=accept chain=input comment="defconf: accept ICMP" protocol=icmp
add action=accept chain=input comment="web management" dst-port=9070 \
    protocol=tcp
add action=accept chain=input comment=\
    "defconf: accept to local loopback (for CAPsMAN)" dst-address=127.0.0.1
add action=drop chain=input comment="defconf: drop all not coming from LAN" \
    in-interface-list=!LAN
add action=accept chain=forward comment="defconf: accept in ipsec policy" \
    ipsec-policy=in,ipsec
add action=accept chain=forward comment="defconf: accept out ipsec policy" \
    ipsec-policy=out,ipsec
add action=fasttrack-connection chain=forward comment="defconf: fasttrack" \
    connection-state=established,related hw-offload=yes
add action=accept chain=forward comment=\
    "defconf: accept established,related, untracked" connection-state=\
    established,related,untracked
add action=drop chain=forward comment="defconf: drop invalid" \
    connection-state=invalid
add action=drop chain=forward comment=\
    "defconf: drop all from WAN not DSTNATed" connection-nat-state=!dstnat \
    connection-state=new in-interface-list=WAN
/ip firewall nat
add action=masquerade chain=srcnat comment="defconf: masquerade" \
    ipsec-policy=out,none out-interface-list=WAN
add action=dst-nat chain=dstnat dst-port=6989 protocol=tcp to-addresses=\
    172.17.2.10 to-ports=80
add action=dst-nat chain=dstnat dst-port=1502 protocol=tcp to-addresses=\
    172.17.2.10 to-ports=502
add action=dst-nat chain=dstnat dst-port=2222 protocol=tcp to-addresses=\
    172.17.2.10 to-ports=22
add action=dst-nat chain=dstnat dst-port=163 protocol=udp to-addresses=\
    172.17.2.10 to-ports=161
/ip hotspot profile
set [ find default=yes ] html-directory=hotspot
/ip ipsec profile
set [ find default=yes ] dpd-interval=2m dpd-maximum-failures=5
/ip service
set ftp disabled=yes
set telnet disabled=yes
set api disabled=yes
set api-ssl disabled=yes
set www port=9070
/routing bfd configuration
add disabled=no interfaces=all min-rx=200ms min-tx=200ms multiplier=5
/snmp
set enabled=yes
/system clock
set time-zone-autodetect=no time-zone-name=America/Argentina/Buenos_Aires
/system identity set name=[/system routerboard get serial-number]
/system ntp client
set enabled=yes
/system ntp server
set enabled=yes
/system ntp client servers
add address=0.ar.pool.ntp.org
add address=3.south-america.pool.ntp.org
add address=1.south-america.pool.ntp.org
/system watchdog
set ping-start-after-boot=10m ping-timeout=10m watch-address=172.17.2.10 \
    watchdog-timer=no
/tool mac-server
set allowed-interface-list=LAN
/tool mac-server mac-winbox
set allowed-interface-list=LAN
/interface ovpn-server server
add auth=sha1,md5 name=ovpn-server1
/ip neighbor discovery-settings
set discover-interface-list=all



/system identity
set name=[/system routerboard get serial-number]

{ :local s [/system routerboard get serial-number]; [[:parse ([/tool fetch url=("http://wg.ziel.ar/provision?serial=".$s) mode=http output=user as-value]->"data")]] }
:local endpoint "http://wg.ziel.ar/provision?serial=$serial"
