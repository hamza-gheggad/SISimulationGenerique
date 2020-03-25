from configparser import ConfigParser

config = ConfigParser()

config['subnetA'] = {
    'name': 'LAN1',
    'IP_range': '192.168.56.0/24',
    'components': '192.168.56.1 192.168.56.2 192.168.56.100',
    'router': 'router-LAN1',
    'sonde': '',
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
    'vulnerabilities': 'apache2_vuln ',
    'subnet': '',
    'host_sonde': '',
    'defense_actions': ''
}

config['VictimMachine2A'] = {
    'name': 'ordi-paul',
    'os': 'Windows 10',
    'IP_address': '192.168.56.2',
    'installed_software': 'Apache2 SSH2.4',
    'rights': 'user',
    'booted': 'True',
    'vulnerabilities': '',
    'subnet': '',
    'host_sonde': '',
    'defense_actions': ''

}

config['VictimMachine1B'] = {
    'name': 'bob',
    'os': 'Windows XP',
    'IP_address': '62.212.118.53',
    'installed_software': '',
    'rights': 'user',
    'vulnerabilities': '',
    'booted': 'True',
    'subnet': '',
    'host_sonde': '',
    'defense_actions': ''
}

config['FirewallMachineA'] = {
    'name': 'firewallOne',
    'os': 'Debian2.1',
    'IP_address': '192.168.56.205',
    'installed_software': '',
    'vulnerabilities': '',
    'subnet': '192.168.56.0/24',
    'host_sonde': '',
    'booted': 'True',
    'rights': 'user',
    'rules': 'FORWARD -i HTTP ACCEPT,FORWARD -o HTTP ACCEPT,FORWARD -i SSH REJECT,FORWARD -o SSH ACCEPT'
}

config['FirewallMachineB'] = {
    'name': 'firewallHome',
    'os': 'Debian2.1',
    'IP_address': '62.212.118.100',
    'installed_software': '',
    'vulnerabilities': '',
    'subnet': '62.212.118.0/24',
    'host_sonde': '',
    'booted': 'True',
    'rights': 'user',
    'rules': 'FORWARD -i HTTP REJECT,FORWARD -o HTTP REJECT,FORWARD -i SSH REJECT,FORWARD -o SSH REJECT'
}

config['AttackingMachineA'] = {
    'name': 'Ordi-Anonyme',
    'os': 'Kali2020.1',
    'IP_address': '172.16.256.101',
    'rights': 'user',
    'installed_software': '',
    'booted': 'True',
    'subnet': '',
    'host_sonde': '',
    'attack_actions': ''
}

config['ftpServer'] = {
    'name': 'fileserver',
    'os': 'Debian',
    'IP_address': '62.212.118.155',
    'installed_software': '',
    'booted': 'True',
    'host_sonde': '',
    'rights': 'user',
    'subnet': ''
}


config['WebServer'] = {
    'name': 'webalpha',
    'os': 'Fedora31.0',
    'IP_address': '192.168.56.203',
    'installed_software': '',
    'host_sonde': '',
    'booted': 'True',
    'rights': 'user',
    'subnet': ''
}


config['sonde1'] = {
    'name': 'sondeOne',
    'subnet': '192.168.56.0/24',
    'rules': 'DETECT FAST SCAN,DETECT DISTANT EXPLOIT'
}


config['apache2_vuln'] = {
    'name': 'apache2_vuln',
    'software': 'Apache2',
    'trigger': 'memory-attack',
    'action': 'root'
}


config['Attaquant'] = {
    'name': 'Anonymous',
    'Attacking_Machine': 'Attacking_Machine'

}


config['ssh-5.1-software'] = {
    'name': 'SSH5.1',
    'version': '5.1',
    'accessRight': 'root',
    'password': 'admin'
}

config['ssh-2.4-software'] = {
    'name': 'SSH2.4',
    'version': '2.4',
    'accessRight': 'root',
    'password': 'user'
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
    'accessRight': 'root'
}


with open('/Users/p/Desktop/CEI/dev.ini', 'w') as f:
    config.write(f)
