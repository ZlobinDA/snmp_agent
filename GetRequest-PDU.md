# Работа с get запросами

За основу была взята инструкция https://lemmy.world/post/962164

## Установка пакетов

Уставнавливаем snmpd + переписываем конфигурацию /etc/snmp/snmpd.conf на конфигурацию по умолчанию

    sudo apt install --reinstall -o Dpkg::Options::="--force-confask,confnew,confmiss" snmp

Уставнавливаем конфигурационные скрипты, MIB'ы и документацию + переписываем /etc/snmp/snmp.conf конфигурацию на конфигурацию по умолчанию

    sudo apt install --reinstall -o Dpkg::Options::="--force-confask,confnew,confmiss" libsnmp-base

Устанавливаем snmp и snmp-mibs-downloader

    sudo apt install snmp snmp-mibs-downloade

Устанавливаем инструменты разработчика

    sudo apt install libsnmp-dev

Перезапускаем сервис агента

    sudo systemctl restart snmpd

Проверяем состояние сервиса

    sudo systemctl status snmpd

Получаем информация с локального хоста

    snmpwalk -v 2c -c public localhost

## Настраиваем окружение для работы с примером

### Добавляем тестовый MIB

Копируем MIB файл из директории config директорию /usr/share/snmp/mibs/

    sudo cp BMC-MIB.txt /usr/share/snmp/mibs/

Проверяем, что данные были добавлены

    snmptranslate -On BMC-MIB::bmcHostPowerState.0

Ответ на запрос

    .1.3.6.1.4.1.56392.0.1.0

### Дополняем конфигурацию /etc/snmp/snmpd.conf

    echo "" | sudo tee -a /etc/snmp/snmpd.conf
    echo "# custom communities" | sudo tee -a /etc/snmp/snmpd.conf
    echo "rocommunity bmc 127.0.0.1 .1.3.6.1.4 # branch for BMC mibs" | sudo tee -a /etc/snmp/snmpd.conf

Перезапускаем сервис агента

    sudo systemctl restart snmpd

Проверяем состояние сервиса

    sudo systemctl status snmpd

Запрашиваем данные из тестового MIB

    snmpget -v 2c -c bmc localhost BMC-MIB::bmcHostPowerState.0

Ответ на запрос

    BMC-MIB::bmcHostPowerState = No Such Object available on this agent at this OID