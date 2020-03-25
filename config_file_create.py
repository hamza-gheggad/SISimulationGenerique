from configparser import ConfigParser

config = ConfigParser()

config['subnetA'] = {
    'name': 'LAN1',
    'IP_range': '192.168.56.0/24',
    'components': '192.168.56.1 192.168.56.2 192.168.56.100',
    'router': 'router-LAN1',
    'sonde': 'sondeA',
    'firewall': '192.168.56.205'
}

config['subnetB'] = {
    'name': 'LAN2',
    'IP_range': '62.212.118.0/24',
    'components': '',
    'router': 'router-LAN2',
    'sonde': '',
    'firewall': '62.212.118.100'
}

config['subnetC'] = {
    'name': 'LAN3',
    'IP_range': '172.16.256.0/24',
    'components': '',
    'router': 'router-LAN2',
    'sonde': '',
    'firewall': ''
}

config['router1'] = {
    'name': 'router-LAN1',
    'subnetsin': '192.168.56.0/24',
    'subnetsout': '62.212.118.0/24 172.16.256.0/24',
    'gateway': 'True'
}

config['router2'] = {
    'name': 'router-LAN2',
    'subnetsin': '62.212.118.0/24',
    'subnetsout': '172.16.256.0/24 192.168.56.0/24',
    'gateway': 'True'
}

config['router3'] = {
    'name': 'router-LAN3',
    'subnetsin': '172.16.256.0/24',
    'subnetsout': '62.212.118.0/24 192.168.56.0/24',
    'gateway': 'True'
}

config['router4'] = {
    'name': 'router-central',
    'subnetsin': '62.212.118.0/24 192.168.56.0/24 172.16.256.0/24',
    'subnetsout': '62.212.118.0/24 192.168.56.0/24 172.16.256.0/24',
    'gateway': 'True'
}

config['VictimMachine1A'] = {
    'name': 'ordi-marie',
    'os': 'Debian2.0',
    'IP_address': '192.168.56.1',
    'installed_software': 'SSH5.1 Apache2 HIDS1',
    'rights': 'user',
    'booted': 'True',
    'vulnerabilities': 'apache2_vuln',
    'subnet': '192.168.56.0/24',
    'host_sonde': 'HIDS1',
    'defense_actions': ''
}

config['VictimMachine2A'] = {
    'name': 'ordi-paul',
    'os': 'Windows10',
    'IP_address': '192.168.56.2',
    'installed_software': 'Mysql3.23.33',
    'rights': 'user',
    'booted': 'True',
    'vulnerabilities': 'mysql3.23.33_vuln',
    'subnet': '192.168.56.0/24',
    'host_sonde': '',
    'defense_actions': ''

}

config['WebServerA'] = {
    'name': 'webserverA',
    'os': 'Fedora31.0',
    'IP_address': '192.168.56.203',
    'installed_software': 'Guacamole Mysql3.23.33',
    'vulnerabilities': 'fedora_vuln mysql3.23.33_vuln',
    'host_sonde': '',
    'booted': 'True',
    'rights': 'user',
    'subnet': '192.168.56.0/24'
}

config['FirewallMachineA'] = {
    'name': 'firewallOne',
    'os': 'Debian2.1',
    'IP_address': '192.168.56.205',
    'installed_software': 'SSH3.1 Apache2',
    'vulnerabilities': 'ssh3.1_vuln apache2_vuln',
    'subnet': '192.168.56.0/24',
    'host_sonde': '',
    'booted': 'True',
    'rights': 'user',
    'rules': 'FORWARD -i HTTP ACCEPT,FORWARD -o HTTP ACCEPT,FORWARD -i SSH REJECT,FORWARD -o SSH ACCEPT'
}

config['VictimMachine1B'] = {
    'name': 'bob',
    'os': 'WindowsXP',
    'IP_address': '62.212.118.53',
    'installed_software': 'Mysql3.23.33',
    'rights': 'user',
    'vulnerabilities': 'mysql3.23.33_vuln windowsxp_vuln',
    'booted': 'True',
    'subnet': '62.212.118.0/24',
    'host_sonde': '',
    'defense_actions': ''
}

config['VictimMachine2B'] = {
    'name': 'alice',
    'os': 'Windows10',
    'IP_address': '62.212.118.55',
    'installed_software': 'Mysql3.23.33 IPSec',
    'rights': 'user',
    'vulnerabilities': 'mysql3.23.33_vuln IPSec_vuln',
    'booted': 'True',
    'subnet': '62.212.118.0/24',
    'host_sonde': '',
    'defense_actions': ''
}

config['ftpServerB'] = {
    'name': 'fileserver',
    'os': 'Debian',
    'IP_address': '62.212.118.155',
    'installed_software': 'Apache2',
    'vulnerabilities': 'apache2_vuln',
    'booted': 'True',
    'host_sonde': '',
    'rights': 'user',
    'subnet': '62.212.118.0/24'
}


config['FirewallMachineB'] = {
    'name': 'firewallB',
    'os': 'Debian2.1',
    'IP_address': '62.212.118.100',
    'installed_software': 'Apache2',
    'vulnerabilities': 'apache2_vuln',
    'subnet': '62.212.118.0/24',
    'host_sonde': '',
    'booted': 'True',
    'rights': 'user',
    'rules': 'FORWARD -i HTTP REJECT,FORWARD -o HTTP REJECT,FORWARD -i SSH REJECT,FORWARD -o SSH REJECT'
}

config['AttackingMachineC'] = {
    'name': 'Ordi-Anonyme',
    'os': 'Kali2020.1',
    'IP_address': '172.16.256.101',
    'rights': 'user',
    'installed_software': '',
    'booted': 'True',
    'subnet': '172.16.256.0/24',
    'host_sonde': '',
    'attack_actions': ''
}

config['VictimMachine1C'] = {
    'name': 'louis',
    'os': 'Mac17.1',
    'IP_address': '172.16.256.11',
    'installed_software': 'SSH3.1 Libtiff3.6.1',
    'rights': 'user',
    'vulnerabilities': 'ssh3.1_vuln libtiff_vuln',
    'booted': 'True',
    'subnet': '172.16.256.0/24',
    'host_sonde': '',
    'defense_actions': ''
}

config['VictimMachine2C'] = {
    'name': 'jean',
    'os': 'Windows10',
    'IP_address': '172.16.256.15',
    'installed_software': 'Mysql3.23.33 IPSec',
    'rights': 'user',
    'vulnerabilities': 'mysql3.23.33_vuln IPSec_vuln',
    'booted': 'True',
    'subnet': '172.16.256.0/24',
    'host_sonde': '',
    'defense_actions': ''
}


config['sondeA'] = {
    'name': 'sondeA',
    'subnet': '192.168.56.0/24',
    'rules': 'DETECT FAST SCAN,DETECT DISTANT EXPLOIT'
}


config['apache2_vuln'] = {
    'name': 'apache2_vuln',
    'software': 'Apache2',
    'trigger': 'bufferoverflow',
    'action': 'root'
}

config['ssh3.1_vuln'] = {
    'name': 'ssh3.1_vuln',
    'software': 'SSH3.1',
    'trigger': 'bufferoverflow',
    'action': 'code-execution'
}

config['fedora_vuln'] = {
    'name': 'fedora_vuln',
    'software': 'guacamole0.6.2',
    'trigger': 'bufferoverflow',
    'action': 'DOS'
}

config['mysql3.23.33_vuln'] = {
    'name': 'mysql3.23.33_vuln',
    'software': 'Mysql3.23.33',
    'trigger': 'bufferoverflow',
    'action': 'code-execution'
}

config['libtiff_vuln'] = {
    'name': 'libtiff_vuln',
    'software': 'libtiff3.6.1',
    'trigger': 'integeroverflow',
    'action': 'DOS'
}

config['ftp_vuln'] = {
    'name': 'libtiff_vuln',
    'software': 'libtiff3.6.1',
    'trigger': 'integeroverflow',
    'action': 'DOS'
}

config['windowsxp_vuln'] = {
    'name': 'windowsxp_vuln',
    'software': 'fp30reg.dll',
    'trigger': 'bufferoverflow',
    'action': 'code-execution'
}

config['IPSec_vuln'] = {
    'name': 'IPSec_vuln',
    'software': 'IPSec',
    'trigger': 'encryptionError',
    'action': 'DOS'
}


config['Attaquant'] = {
    'name': 'Anonymous',
    'Attacking_Machine': 'Attacking_Machine'

}

config['Guacamole-0.6.2-software'] = {
    'name': 'Guacamole',
    'version': '0.6.2',
    'accessRight': 'user'
}

config['fp30reg.dll-software'] = {
    'name': 'fp30reg.dll',
    'version': '0.0',
    'accessRight': 'user'
}

config['Libtiff-3.6.1-software'] = {
    'name': 'Libtiff3.6.1',
    'version': '3.6.1',
    'accessRight': 'user'
}

config['ssh-5.1-software'] = {
    'name': 'SSH5.1',
    'version': '5.1',
    'accessRight': 'root',
    'password': 'admin'
}

config['IPSec-software'] = {
    'name': 'IPSec',
    'version': '0.0',
    'accessRight': 'user',
    'password': 'admin'
}

config['ssh-3.1-software'] = {
    'name': 'SSH3.1',
    'version': '3.1',
    'accessRight': 'root',
    'password': 'user'
}

config['mysql-3.23.33-software'] = {
    'name': 'Mysql3.23.33',
    'version': '3.23.33',
    'accessRight': 'user'

}
config['HIDS1'] = {
    'name': 'HIDS1',
    'version': '10.2',
    'rules': 'DETECT SERVICE SCAN',
    'accessRight': 'root'
}


config['Apache-software'] = {
    'name': 'Apache2',
    'version': '2.2',
    'accessRight': 'user'
}


with open('/Users/p/Desktop/CEI/dev.ini', 'w') as f:
    config.write(f)
