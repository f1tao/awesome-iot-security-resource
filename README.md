# Awesome iot security resource

## Fundamental

* [WHAT HAPPENS WHEN YOUR ROUTER IS HACKED?](https://nordsecurity.com/blog/what-happens-when-router-is-hacked)
* [IoT Reverse Engineering](https://mp.weixin.qq.com/s/_pzsmZZz9cTcOxIl0cDgGQ)
* [Embedded Systems Security and TrustZone](https://embeddedsecurity.io/index.html)
* [CH32V003 PROGRAMMING: HOW TO USE UART](https://pallavaggarwal.in/2023/09/23/ch32v003-programming-uart/)

## Vulnerability Writeup

### Cisco

* [Cisco IOS XE CVE-2023-20198 and CVE-2023-20273: WebUI Internals, Patch Diffs, and Theory Crafting](https://www.horizon3.ai/cisco-ios-xe-cve-2023-20198-theory-crafting/)
* [Cisco IOS XE CVE-2023-20198: Deep Dive and POC](https://www.horizon3.ai/cisco-ios-xe-cve-2023-20198-deep-dive-and-poc/)
* [Analysis of Unauthenticated Command Execution Vulnerability in Cisco IOS XE System WebUI](https://paper.seebug.org/3073/)
* [Cisco RV130 – It’s 2019, but yet: strcpy](https://www.pentestpartners.com/security-blog/cisco-rv130-its-2019-but-yet-strcpy/)
* [Exploiting CVE-2019-1663](https://quentinkaiser.be/exploitdev/2019/08/30/exploit-cve-2019-1663/)
* [Breaking Cisco RV110W, RV130, RV130W, and RV215W. Again.](https://quentinkaiser.be/exploitdev/2020/07/14/breaking-cisco-rv-again/)
* [Ghetto Patch Diffing a Cisco RV110W Firmware Update](https://quentinkaiser.be/exploitdev/2020/09/23/ghetto-patch-diffing-cisco/)
* [Patch Diffing a Cisco RV110W Firmware Update (Part II)](https://quentinkaiser.be/exploitdev/2020/10/01/patch-diffing-cisco-rv110/)

### Citrix

* [Reversing Citrix Gateway for XSS](https://blog.assetnote.io/2023/06/29/binary-reversing-citrix-xss/)
* [Analysis of CVE-2023-3519 in Citrix ADC and NetScaler Gateway](https://blog.assetnote.io/2023/07/21/citrix-CVE-2023-3519-analysis/)
* [Analysis of CVE-2023-3519 in Citrix ADC and NetScaler Gateway (Part 2)](https://blog.assetnote.io/2023/07/21/citrix-CVE-2023-3519-analysis/)
* [CVE-2023-3519](https://attackerkb.com/topics/si09VNJhHh/cve-2023-3519)

### F5 BIG-IP

* [CVE-2022-41622 and CVE-2022-41800 (FIXED): F5 BIG-IP and iControl REST Vulnerabilities and Exposures](https://www.rapid7.com/blog/post/2022/11/16/cve-2022-41622-and-cve-2022-41800-fixed-f5-big-ip-and-icontrol-rest-vulnerabilities-and-exposures/)
* [CVE-2023-22374: F5 BIG-IP Format String Vulnerability](https://www.rapid7.com/blog/post/2023/02/01/cve-2023-22374-f5-big-ip-format-string-vulnerability/)
* [Refresh: Compromising F5 BIG-IP With Request Smuggling | CVE-2023-46747](https://www.praetorian.com/blog/refresh-compromising-f5-big-ip-with-request-smuggling-cve-2023-46747/)

### Fortigate

* [Attacking SSL VPN - Part 2: Breaking the Fortigate SSL VPN](https://blog.orange.tw/2019/08/attacking-ssl-vpn-part-2-breaking-the-fortigate-ssl-vpn.html)
* [Producing a POC for CVE-2022-42475 (Fortinet RCE)](https://blog.scrt.ch/2023/03/14/producing-a-poc-for-cve-2022-42475-fortinet-rce/)
* [CVE-2022-42475](https://wzt.ac.cn/2022/12/15/CVE-2022-42475/)
* [Xortigate, or CVE-2023-27997 - The Rumoured RCE That Was](https://labs.watchtowr.com/xortigate-or-cve-2023-27997/)
* [XORtigate: Pre-authentication Remote Code Execution on Fortigate VPN (CVE-2023-27997)](https://blog.lexfo.fr/xortigate-cve-2023-27997.html)
* [HEXACON2023 - XORtigate: zero-effort, zero-expense, 0-day on Fortinet SSL VPN by Charles Fol](https://www.youtube.com/watch?v=7yxTI_4vPGk)
* [CVE-2023-27997-FortiGate-SSLVPN-HeapOverflow](https://bestwing.me/CVE-2023-27997-FortiGate-SSLVPN-Heap-Overflow.html)
* [Breaking Fortinet Firmware Encryption](https://bishopfox.com/blog/breaking-fortinet-firmware-encryption)
* [Building an Exploit for FortiGate Vulnerability CVE-2023-27997](https://bishopfox.com/blog/building-exploit-fortigate-vulnerability-cve-2023-27997)

### Pulse Secure

* [Attacking SSL VPN - Part 3: The Golden Pulse Secure SSL VPN RCE Chain, with Twitter as Case Study!](https://blog.orange.tw/2019/09/attacking-ssl-vpn-part-3-golden-pulse-secure-rce-chain.html)

### Palo Alto

* [Attacking SSL VPN - Part 1: PreAuth RCE on Palo Alto GlobalProtect, with Uber as Case Study!](https://blog.orange.tw/2019/07/attacking-ssl-vpn-part-1-preauth-rce-on-palo-alto.html)

### Juniper

* [CVE-2023-36844 And Friends: RCE In Juniper Devices](https://labs.watchtowr.com/cve-2023-36844-and-friends-rce-in-juniper-firewalls/)
* [Fileless Remote Code Execution on Juniper Firewalls](https://vulncheck.com/blog/juniper-cve-2023-36845)

### SonicWall

* [一种 SonicWall nsv 虚拟机的解包方法](https://www.anquanke.com/post/id/266078)
* [Ghost In The Wire, Sonic In The Wall - Adventures With SonicWall](https://labs.watchtowr.com/ghost-in-the-wire-sonic-in-the-wall/)

### VxWroks

* [Wind River VxWorks tarExtract directory traversal vulnerability (CVE-2023-38346)](https://www.pentagrid.ch/en/blog/wind-river-vxworks-tarextract-directory-traversal-vulnerability/)

### MikroTik

* [Pulling MikroTik into the Limelight](https://margin.re/2022/06/pulling-mikrotik-into-the-limelight/)

### Netgear

* [CVE-2021-33514：Netgear 多款交换机命令注入漏洞](https://paper.seebug.org/1645/)
* [Feral Terror vulnerability (some NETGEAR smart switches UPDATED 3](https://gynvael.coldwind.pl/?id=733)
* [Seventh Inferno vulnerability (some NETGEAR smart switches)](https://gynvael.coldwind.pl/?id=742)
* [Draconian Fear vulnerability (some NETGEAR smart switches)](https://gynvael.coldwind.pl/?id=741)
* [COOL VULNS DON'T LIVE LONG - NETGEAR AND PWN2OWN](https://www.synacktiv.com/publications/cool-vulns-dont-live-long-netgear-and-pwn2own.html)
* [PwnAgent: A One-Click WAN-side RCE in Netgear RAX Routers with CVE-2023-24749](https://mahaloz.re/2023/02/25/pwnagent-netgear.html)
* [Puckungfu: A NETGEAR WAN Command Injection](https://research.nccgroup.com/2022/12/22/puckungfu-a-netgear-wan-command-injection/)
* [CVE-2022-27643 - NETGEAR R6700v3 upnpd Buffer Overflow Remote Code Execution Vulnerability](https://blog.relyze.com/2022/03/cve-2022-27643-netgear-r6700v3-upnpd.html)
* [nday exploit: netgear orbi unauthenticated command injection (cve-2020-27861)](https://blog.coffinsec.com/research/2022/07/02/orbi-nday-exploit-cve-2020-27861.html)
* [NETGEAR NIGHTHAWK R7000P UPNPD BUFFER OVERFLOW REMOTE CODE EXECUTION VULNERABILITY](https://hdwsec.fr/blog/20230201-netgear/)
* [Reverse Engineering a Netgear Nday](https://starkeblog.com/netgear/nday/2022/03/13/reverse-engineering-a-netgear-nday.html)
* [Analyzing an Old Netatalk dsi_writeinit Buffer Overflow Vulnerability in NETGEAR Router](https://medium.com/@cq674350529/analyzing-an-old-netatalk-dsi-writeinit-buffer-overflow-vulnerability-in-netgear-router-4e9d59064584)
* [NETGEAR NIGHTHAWK R7000P AWS_JSON UNAUTHENTICATED DOUBLE STACK OVERFLOW VULNERABILITY](https://hdwsec.fr/blog/20221109-netgear/)
* [Our Pwn2Own journey against time and randomness (part 1)](https://blog.quarkslab.com/our-pwn2own-journey-against-time-and-randomness-part-1.html)
* [Our Pwn2Own journey against time and randomness (part 2)](https://blog.quarkslab.com/our-pwn2own-journey-against-time-and-randomness-part-2.html)
* [Pwn2Own Toronto 22: Exploit Netgear Nighthawk RAX30 Routers](https://claroty.com/team82/research/chaining-five-vulnerabilities-to-exploit-netgear-nighthawk-rax30-routers-at-pwn2own-toronto-2022)

### Zyxel

* [Zyxel firmware extraction and password analysis](https://security.humanativaspa.it/zyxel-firmware-extraction-and-password-analysis/)
* [Multiple vulnerabilities in Zyxel zysh](https://security.humanativaspa.it/multiple-vulnerabilities-in-zyxel-zysh/)
* [Zyxel authentication bypass patch analysis (CVE-2022-0342)](https://security.humanativaspa.it/zyxel-authentication-bypass-patch-analysis-cve-2022-0342/)
* [Useless path traversals in Zyxel admin interface (CVE-2022-2030)](https://security.humanativaspa.it/useless-path-traversals-in-zyxel-admin-interface-cve-2022-2030/)

### TOTOLINK

* [TOTOLINK T10旧版本漏洞挖掘和分析](https://blingblingxuanxuan.github.io/2021/09/25/analysis-of-totolink-t10)
* [TOTOLink T6路由器漏洞复现](https://blog.csdn.net/qq_41667409/article/details/122441295)
* [TOTOLINK NR1800X 系列 CVE 分析](https://paper.seebug.org/1995)

### Tenda

* [Vulnerabilities in Tenda's W15Ev2 AC1200 Router](https://boschko.ca/tenda_ac1200_router/)
* [Tenda AX12 路由器设备分析（一）](https://www.anquanke.com/post/id/255290)
* [Tenda AX12路由器设备分析（二）之UPnP协议](https://www.anquanke.com/post/id/263170)
* [Tenda AX12 路由器设备分析（三）之OpenWrt 浅析](https://www.anquanke.com/post/id/264194)

###  GL.iNET

* [Vulnerabilities and Hardware Teardown of GL.iNET GL-MT300N-V2 Router](https://boschko.ca/glinet-router/)

### Vigor

* [draytek漏洞分析](https://www.freebuf.com/vuls/262765.html)
* [DrayTek Vigor企业级路由器和交换机设备在野0-day 漏洞分析报告](https://blog.netlab.360.com/two-zero-days-are-targeting-draytek-broadband-cpe-devices/)
* [DrayTek Vigor 2960 从未授权到rce](https://bestwing.me/drayteck-vigor-vulnerability-disclosure.html)
* [CVE-2020-8515 漏洞分析与利用](https://www.hayasec.me/2020/03/31/cve-2020-8515/)
* [Vigor2960漏洞复现（CVE-2020-14472）](https://nosec.org/home/detail/4631.html)

### TP-LINK

* [When an N-Day turns into a 0day. (Part 1 of 2)](https://github.com/b1ack0wl/vulnerability-write-ups/blob/master/TP-Link/WR940N/112022/Part1.md)
* [Remote code execution as root from the local network on TP-Link SR20 routers](https://mjg59.dreamwidth.org/51672.html)
* [TP-Link AC1750 (Pwn2Own 2019)](https://labs.withsecure.com/advisories/tp-link-ac1750-pwn2own-2019)
* [EXPLOITING THE TP-LINK ARCHER A7 AT PWN2OWN TOKYO](https://www.zerodayinitiative.com/blog/2020/4/6/exploiting-the-tp-link-archer-c7-at-pwn2own-tokyo)
* [PWN2OWN TOKYO 2020: DEFEATING THE TP-LINK AC1750](https://www.synacktiv.com/en/publications/pwn2own-tokyo-2020-defeating-the-tp-link-ac1750.html)

### D-Link

* [THE ANATOMY OF A BUG DOOR: DISSECTING TWO D-LINK ROUTER AUTHENTICATION BYPASSES](https://www.zerodayinitiative.com/blog/2020/9/30/the-anatomy-of-a-bug-door-dissecting-two-d-link-router-authentication-bypasses)
* [Debugging D-Link: Emulating firmware and hacking hardware](https://www.greynoise.io/blog/debugging-d-link-emulating-firmware-and-hacking-hardware)
* [D-Link DIR-816 A2路由器安全研究分享](https://paper.seebug.org/1036/)
* [Reverse Engineering a D-Link Backdoor](https://lcx.cc/post/3950/)
* [D-Link DAP-X1860: Remote Command Injection](https://www.redteam-pentesting.de/en/advisories/rt-sa-2023-006/-d-link-dap-x1860-remote-command-injection)

### XiaoMI

* [实战逻辑漏洞：三个漏洞搞定一台路由器](https://zhuanlan.zhihu.com/p/245070099)
* [【长亭HITCON演讲视频】如何从零开始攻破一台明星IoT设备](https://www.bilibili.com/video/BV1gf4y1D7L2)
* [Exploit (Almost) All Xiaomi Routers Using Logical Bugs](https://hitcon.org/2020/slides/Exploit%20(Almost)%20All%20Xiaomi%20Routers%20Using%20Logical%20Bugs.pdf)
* [小米R3A和R4系列路由器远程命令执行漏洞（CVE-2019-18370，CVE-2019-18371）](https://github.com/UltramanGaia/Xiaomi_Mi_WiFi_R3G_Vulnerability_POC/blob/master/report/report.md)
* [关于我们在强网杯上小米路由器非预期解这件小事](https://www.anquanke.com/post/id/247597)
* [强网杯 2021 线下 RW Mi Router](https://xuanxuanblingbling.github.io/iot/2021/07/15/mirouter/)
* [Xiaomi AI Speaker Authenticated RCE I: Firmware Analysis](https://blog.csftech.net/xiaomi-ai-speaker-authenticated-rce-i-firmware-analysis/)
* [Xiaomi AI Speaker Authenticated RCE II: How Does MICO OTA Update Work?](https://blog.csftech.net/xiaomi-ai-speaker-authenticated-rce-ii-how-does-mico-ota-update-work/)
* [Xiaomi AI Speaker Authenticated RCE III: CVE-2020-14096](https://blog.csftech.net/xiaomi-ai-speaker-authenticated-rce-iii-cve-2020-14096/)
* [DEFCON 26-Having fun with IoT: Reverse Engineering and Hacking of Xiaomi IoT Devices](https://media.defcon.org/DEF%20CON%2026/DEF%20CON%2026%20presentations/DEFCON-26-Dennis-Giese-Having-Fun-With-IOT-Updated.pdf)
* [I hacked MiBand 3, and here is how I did it. Part I](https://medium.com/@yogeshojha/i-hacked-xiaomi-miband-3-and-here-is-how-i-did-it-43d68c272391)
* [I hacked MiBand 3, and here is how I did it Part II — Reverse Engineering to upload Firmware and Resources Over the Air](https://medium.com/@yogeshojha/i-hacked-miband-3-and-here-is-how-i-did-it-part-ii-reverse-engineering-to-upload-firmware-and-b28a05dfc308)
* [Hack Routers, Get Toys: Exploiting the Mi Router 3](https://blog.securityevaluators.com/hack-routers-get-toys-exploiting-the-mi-router-3-1d7fd42f0838)
* [Show Mi The Vulns: Exploiting Command Injection in Mi Router 3](https://blog.securityevaluators.com/show-mi-the-vulns-exploiting-command-injection-in-mi-router-3-55c6bcb48f09)
* [Xiaomi Wi-Fi Repeater Analysis — IoT Exploitation/Research](https://k4r4koyun.medium.com/xiaomi-wi-fi-repeater-analysis-iot-exploitation-research-6c689ce196a5)
* [Custom Firmware for the Xiaomi AX3600 Wireless Router](https://irq5.io/2020/08/10/custom-firmware-for-the-xiaomi-ax3600-wireless-router/)
* [物联网设备消息总线机制的使用及安全问题](https://gtrboy.github.io/posts/bus/)
* [Rooting Xiaomi WiFi Routers](https://blog.thalium.re/posts/rooting-xiaomi-wifi-routers/)

### NAS

* [A Pain in the NAS: Exploiting Cloud Connectivity to PWN your NAS: WD PR4100 Edition](https://claroty.com/team82/research/a-pain-in-the-nas-exploiting-cloud-connectivity-to-pwn-your-nas-wd-pr4100-edition)
* [A Pain in the NAS: Exploiting Cloud Connectivity to PWN your NAS: Synology DS920+ Edition](https://claroty.com/team82/research/a-pain-in-the-nas-exploiting-cloud-connectivity-to-pwn-your-nas-synology-ds920-edition)
* [Synology NAS DSM Account Takeover: When Random is not Secure](https://claroty.com/team82/research/synology-nas-dsm-account-takeover-when-random-is-not-secure)

### Camera

* [HiSilicon DVR hack](https://github.com/tothi/pwn-hisilicon-dvr/tree/42d8325e68fdb075fe27df8a269932f9fa9601a6)
* [Exploiting: Buffer overflow in Xiongmai DVRs](https://blog.ret2.me/post/2022-01-26-exploiting-xiongmai-dvrs/)
* [Hacking the Furbo Dog Camera: Part I](https://www.somersetrecon.com/blog/2021/hacking-the-furbo-part-1)
* [Hacking the Furbo Dog Camera: Part II](https://www.somersetrecon.com/blog/2021/hacking-the-furbo-dog-camera-part-ii)
* [Hacking the Furbo Dog Camera: Part III Fun with Firmware](https://www.somersetrecon.com/blog/2022/hacking-the-furbo-dog-camera-part-iii)
* [Hacking a Tapo TC60 Camera](https://medium.com/@two06/hacking-a-tapo-tc60-camera-e6ce7ca6cad1)

### BootLoader

* [Technical Advisory – U-Boot – Unchecked Download Size and Direction in USB DFU (CVE-2022-2347)](https://research.nccgroup.com/2023/01/20/technical-advisory-u-boot-unchecked-download-size-and-direction-in-usb-dfu-cve-2022-2347/)
* [[胖猴小玩闹] 智能门锁与网关番外二： 云丁鹿客门锁中bootloader和FreeRTOS的分析](https://mp.weixin.qq.com/s?__biz=MzI1MDQ5MzA4NA==&mid=2247484014&idx=1&sn=4c6c8d72837a9a1ced3d158b8c3527c0)
* [Breaking Secure Boot on the Silicon Labs Gecko platform](https://blog.quarkslab.com/breaking-secure-boot-on-the-silicon-labs-gecko-platform.html)

### Printer

* [Bypassing software update package encryption – extracting the Lexmark MC3224i printer firmware (part 1)](https://research.nccgroup.com/2022/02/17/bypassing-software-update-package-encryption-extracting-the-lexmark-mc3224i-printer-firmware-part-1/)
* [Analyzing a PJL directory traversal vulnerability – exploiting the Lexmark MC3224i printer (part 2)](https://research.nccgroup.com/2022/02/18/analyzing-a-pjl-directory-traversal-vulnerability-exploiting-the-lexmark-mc3224i-printer-part-2/)
* [DryOS PIXMA Printer Shell](https://chdk.fandom.com/wiki/DryOS_PIXMA_Printer_Shell)
* [A Sheep in Wolf’s Clothing – Finding RCE in HP’s Printer Fleet](https://foxglovesecurity.com/2017/11/20/a-sheep-in-wolfs-clothing-finding-rce-in-hps-printer-fleet/)
* [FAXPLOIT: SENDING FAX BACK TO THE DARK AGES](https://research.checkpoint.com/2018/sending-fax-back-to-the-dark-ages/)
* [TREASURE CHEST PARTY QUEST: FROM DOOM TO EXPLOIT](https://synacktiv.com/publications/treasure-chest-party-quest-from-doom-to-exploit.html)
* [Pwn2Own 2021 Canon ImageCLASS MF644Cdw writeup](https://doar-e.github.io/blog/2022/06/11/pwn2own-2021-canon-imageclass-mf644cdw-writeup/)
* [Your printer is not your printer ! - Hacking Printers at Pwn2Own Part I](https://devco.re/blog/2023/10/05/your-printer-is-not-your-printer-hacking-printers-pwn2own-part1-en/)
* [Your printer is not your printer ! - Hacking Printers at Pwn2Own Part II](https://devco.re/blog/2023/11/06/your-printer-is-not-your-printer-hacking-printers-pwn2own-part2-en/)
* [【hitcon2022】Your printer is not your printer ! - Hacking Printers at Pwn2Own](https://hitcon.org/2022/slides/Your%20Printer%20is%20not%20your%20Printer%20!%20-%20Hacking%20Printers%20at%20Pwn2Own.pdf)

### Car

* [How I Hacked my Car](https://programmingwithstyle.com/posts/howihackedmycar/)
* [How I Hacked my Car Part 2: Making a Backdoor](https://programmingwithstyle.com/posts/howihackedmycarpart2/)
* [How I Hacked my Car Part 3: Making Software](https://programmingwithstyle.com/posts/howihackedmycarpart3/)
* [NFC RELAY ATTACK ON TESLA MODEL Y](https://act-on.ioactive.com/acton/attachment/34793/f-6460b49e-1afe-41c3-8f73-17dc14916847/1/-/-/-/-/NFC-relay-TESlA_JRoriguez.pdf)
* [浅谈车机IVI漏洞挖掘](https://xz.aliyun.com/t/12988)
* [新型车机，如何攻防？](https://blog.nsfocus.net/tbox/)
* [Rooting Bosch lcn2kai Headunit](https://github.com/ea/bosch_headunit_root)
* [APK逆向分析入门-以某车载音乐APP为例](https://xz.aliyun.com/t/12972)

### Smart Speaker

* [DEFCON-26-Breaking-Smart-Speakers](https://media.defcon.org/DEF%20CON%2026/DEF%20CON%2026%20presentations/DEFCON-26-Wu-HuiYu-and-Qian-Wenxiang-Breaking-Smart-Speakers-Updated.pdf)

### Protocol

* [From MQTT Fundamentals to CVE](https://blog.compass-security.com/2023/09/from-mqtt-fundamentals-to-cve/)

### Other

* [Tetsuji: Remote Code Execution on a GameBoy Colour 22 Years Later](https://xcellerator.github.io/posts/tetsuji/)

## Exploitation Method

### Uninitialized Pointer  Vulnerability

* [When an N-Day turns into a 0day. (Part 1 of 2)](https://github.com/b1ack0wl/vulnerability-write-ups/blob/master/TP-Link/WR940N/112022/Part1.md)

### Heap Spray

* [MeshyJSON: A TP-Link tdpServer JSON Stack Overflow](https://research.nccgroup.com/2022/12/19/meshyjson-a-tp-link-tdpserver-json-stack-overflow/)

### BSS Overflow

* [CVE-2022-27643 - NETGEAR R6700v3 upnpd Buffer Overflow Remote Code Execution Vulnerability](https://blog.relyze.com/2022/03/cve-2022-27643-netgear-r6700v3-upnpd.html)

### Heap Overflow

* [Analyzing an Old Netatalk dsi_writeinit Buffer Overflow Vulnerability in NETGEAR Router](https://medium.com/@cq674350529/analyzing-an-old-netatalk-dsi-writeinit-buffer-overflow-vulnerability-in-netgear-router-4e9d59064584)

## Hardware Crack

* [Exception(al) Failure - Breaking the STM32F1 Read-Out Protection](https://blog.zapb.de/stm32f1-exceptional-failure/)
* [Pwn the ESP32 crypto-core](https://limitedresults.com/2019/08/pwn-the-esp32-crypto-core/)
* [HARDWARE HACKING 101: IDENTIFYING AND DUMPING EMMC FLASH](https://www.riverloopsecurity.com/blog/2020/03/hw-101-emmc/)
* [Extract Firmware from OT Devices for Vulnerability Research](https://www.nozominetworks.com/blog/extract-firmware-from-ot-devices-for-vulnerability-research/)
* [Methods for Extracting Firmware from OT Devices for Vulnerability Research](https://www.nozominetworks.com/blog/methods-for-extracting-firmware-from-ot-devices-for-vulnerability-research/)
* [Hacking Some More Secure USB Flash Drives (Part I)](https://blog.syss.com/posts/hacking-usb-flash-drives-part-1/)
* [Hacking Some More Secure USB Flash Drives (Part II)](https://blog.syss.com/posts/hacking-usb-flash-drives-part-2/)

### Fault Injection

* [Bypassing Secure Boot using Fault Injection](https://raelize.com/upload/research/2016/2016_BlackHat-EU_Bypassing-Secure-Boot-Using-Fault-Injection_NT-AS.pdf)
* [KERNELFAULT: R00ting the Unexploitable using Hardware Fault Injection](https://raelize.com/upload/research/2017/2017_BlueHat-v17_KERNELFAULT-R00ting-the-Unexploitable-using-Hardware-Fault-Injection_CM_NT.pdf)
* [KERNELFAULT: Pwning Linux using Hardware Fault Injection](https://raelize.com/upload/research/2017/2017_Hardwear-io_Escalating-Privileges-in-Linux-using-Fault-Injection_NT-CM.pdf)
* [HARDENING SECURE BOOT ON EMBEDDED DEVICES FOR HOSTILE ENVIRONMENTS](https://raelize.com/upload/research/2019/2019_BlueHat-IL_Hardening-Secure-Boot-on-Embedded-Devices-for-Hostile-Environments_NT-AS-CM.pdf)

## Firmware

### Firmware Emulation

* [Emulating IoT Firmware Made Easy: Start Hacking Without the Physical Device](https://boschko.ca/qemu-emulating-firmware/)

### Firmware Analysis

* [IoT漏洞研究（一）固件基础](https://www.freebuf.com/articles/endpoint/254257.html)
* [OpenWRT中的Flash简析](https://mp.weixin.qq.com/s?__biz=Mzg3NzczOTA3OQ==&mid=2247486018&idx=1&sn=d1a2a1bccb2376cb7197423f8ebb788a)

### Firmware Extraction

* [MindShare: Dealing With Encrypted Router Firmware](https://www.zerodayinitiative.com/blog/2020/2/6/mindshare-dealing-with-encrypted-router-firmware)
* [Zyxel firmware extraction and password analysis](https://security.humanativaspa.it/zyxel-firmware-extraction-and-password-analysis/)
* [Reverse Engineering Yaesu FT-70D Firmware Encryption](https://landaire.net/reversing-yaesu-firmware-encryption/)
* [Bypassing software update package encryption – extracting the Lexmark MC3224i printer firmware (part 1)](https://research.nccgroup.com/2022/02/17/bypassing-software-update-package-encryption-extracting-the-lexmark-mc3224i-printer-firmware-part-1/)
* [Intro to Embedded RE: UART Discovery and Firmware Extraction via UBoot](https://voidstarsec.com/blog/uart-uboot-and-usb)
* [Breaking Fortinet Firmware Encryption](https://bishopfox.com/blog/breaking-fortinet-firmware-encryption)

## Specification

* [FastCGI Developer's Kit](http://fastcgi-archives.github.io/fcgi2/doc/overview.html)
* [The Common Gateway Interface (CGI) Version 1.1](https://www.rfc-editor.org/rfc/rfc3875)

## Tool

### Firmware Emulation

* [firmadyne](https://github.com/firmadyne/firmadyne)

### Firmware Extraction

* [binwalk](https://github.com/ReFirmLabs/binwalk)
* [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
* [unblob](https://github.com/onekey-sec/unblob)
* [ofrak](https://github.com/redballoonsecurity/ofrak)

### Firmware Analysis

* [firmwalker](https://github.com/craigz28/firmwalker)

* [emba](https://github.com/e-m-b-a/emba)

* [pyrrha](https://github.com/quarkslab/pyrrha)

  A filesystem cartography and correlation software focusing on visualization.
  
* [rbasefind](https://github.com/sgayou/rbasefind)

  A firmware base address search tool.

### Debug Tool

* [gdb-static-cross](https://github.com/stayliv3/gdb-static-cross/tree/master/prebuilt)

  A simple shell script and two bash sourceable scripts used to build a static gdb-7.12 gdbserver using cross-compiler setups

* [gdb-static](https://github.com/hugsy/gdb-static)

  Public repository of statically compiled GDB and GDBServer

### Other

* [bkcrack](https://github.com/kimci86/bkcrack)

* [mips-binaries](https://github.com/darkerego/mips-binaries)

  Various binaries for the mips architecture

## Blog

* [ONE KEY](https://onekey.com/research/)
* [HN Security](https://security.humanativaspa.it/category/news/)
* [gynvael.coldwind//vx.log](https://gynvael.coldwind.pl/?blog=1)
* [nccgroup](https://research.nccgroup.com/)
* [HDW Sec](https://hdwsec.fr/#blog)
* [River Loop Security](https://www.riverloopsecurity.com/blog/)
* [Team82](https://claroty.com/team82/research)
* [watchTowr Labs](https://labs.watchtowr.com/)
