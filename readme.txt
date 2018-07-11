Утилита для быстрого просмотра соседей по протоколу CDP.
Заменяет набор комманд в консоли, выводит сразу все необходимое.
Использует протокол SNMP для получения информации (Библиотека от Zoho WebNMS)

Пример вывода:
C:\Users\Oleg\go\src\cdpn>cdpn -v v3 -u SNMPUSER1-U -a SHA -w testpass123 -pp AES-128 -s testpass123 192.168.1.10
Host IP: 192.168.1.10
Hostname: Switch.powerc.local
Platform: Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE10, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2015 by Cisco Systems, Inc.
Compiled Wed 11-Feb-15 11:46 by prod_rel_team


Local Port        Neighbor ID                     Neighbor Port          Neighbor Platform          Neighbor IP
---------------   ---------------                 ---------------        --------------------       ---------------
Gi0/5             esxi1.powerc.local              vmnic1                 VMware ESX                 0.0.0.0
Gi0/6             WLCv                            GigabitEthernet0/0/1   AIR-CTVM-K9                192.168.1.192
Gi0/44            APc471.feb3.ce22.POWERC.LOCAL   GigabitEthernet0.1     cisco AIR-LAP1252AG-E-K9   192.168.1.164
Gi0/45            SEP002290BAD777                 Port 1                 Cisco IP Phone 7906        192.168.1.168

Принимает параметры:
-v версия, если v3 то нужно указать -u имя пользователя -a тип хэша -w пароль на хэширование -pp протокол шифрования
-s пароль на шифрование
обязательный параметр: IP адрес коммутатора.

Работает с коммутаторами Cisco включая Nexus