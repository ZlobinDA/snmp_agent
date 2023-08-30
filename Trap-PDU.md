# Работа с trap сигналами
Демонстрация работы с trap сигналами на примере ОС Ubuntu

## Установка и настройка snmptrapd

### Устанавливаем пакеты

snmp

    sudo apt install snmp

snmpd

    sudo apt install snmpd

snmptrad

    sudo apt install snmptrapd

### Останавливаем сервисы snmp

snmpd.service

    sudo systemctl stop snmpd.service

snmptrapd.socket

    sudo systemctl stop snmptrapd.socket

### Настраиваем snmptrapd

В конфигурационном файле /etc/snmp/snmptrapd.conf нужно добавить строки

#### SNMPv2c

    authCommunity log,execute,net public

#### SNMPv3

noAuthNoPriv

    createUser -e 0x0102030405 user1
    authUser log,execute user1 noauth

authNoPriv

    createUser -e 0x0203040506 user2 SHA authPass123
    authUser log,execute user2

authPriv

    createUser -e 0x0304050607 user3 SHA authPass123 AES privPass123
    authUser log,execute user3

### Запускаем snmptrapd вручную

    sudo snmptrapd -Dusm -f -L o

-D - запуск с выводом всей отладочной информации

-Dusm - запуск с выводом информации об авторизации пользователя

В новом терминале проверяем статус и конфигурацию smpd

    sudo netstat -nlup | grep 162

Ожидаемый вывод

    udp        0      0 0.0.0.0:162             0.0.0.0:*                           4784/snmptrapd  

## Отправка тестовых сигналов
### Локальный тестовый сигнал
В новом терминале отправляем тестовый сигнал на себя

#### SNMPv2c

    sudo snmptrap -c public -v 2c 127.0.0.1 "" 1.3.3.3.3.3.3.3 1.2.2.2.2.2.2 s "v2c TRAP"

#### SNMPv3

noAuthNoPriv

    snmptrap -e 0x0102030405 -v 3 -u user1 -l noAuthNoPriv 127.0.0.1 "" 1.3.3.3.3.3.3.3 1.2.2.2.2.2.2 s "v3 noAuthNoPriv TRAP"

authNoPriv

    snmptrap -e 0x0203040506 -v 3 -u user2 -a SHA -A authPass123 -l authNoPriv 127.0.0.1 "" 1.3.3.3.3.3.3.3 1.2.2.2.2.2.2 s "v3 authNoPriv TRAP"

authPriv

    snmptrap -e 0x0304050607 -v 3 -u user3 -a SHA -A authPass123 -x AES -X privPass123 -l authPriv 127.0.0.1 "" 1.3.3.3.3.3.3.3 1.2.2.2.2.2.2 s "v3 authPriv TRAP"


В терминале с запущенным snmptrapd подтверждаем получение сигнала.


### CLI command for manual build:
g++ main.cpp snmp.cpp -L/usr/local/lib -lnetsnmp

### GetRequest-PDU
MIBS:
net-snmp-config --default-mibdirs
snmptranslate -m +NET-SNMP-TUTORIAL-MIB -IR -On nstAgentSubagentObject
snmptranslate -On NET-SNMP-TUTORIAL-MIB::nstAgentSubagentObject.0

Запросить нехватающие mib'ы:
apt install snmp-mibs-downloader

