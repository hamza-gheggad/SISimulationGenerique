from agents import *
from configparser import ConfigParser

parser = ConfigParser()
parser.read('dev.ini')

Victim_Machines = []
Attack_Machines = []
Servers = []
Vulnerabilities = []
Routers = []
Sondes = []
Subnets = []
Firewalls = []
Services = []


for section in parser.sections():
    if 'software' in section:

        SF = Software()
        args = parser.options(section)
        for arg in args:
            if arg == 'name':
                SF.name = parser.get(section, arg)
            if arg == 'version':
                SF.version = parser.get(section, arg)
            if arg == 'accessright':
                SF.accessRight = parser.get(section, arg)
            if arg == 'password':
                SF.password = parser.get(section, arg)
        Services.append(SF)

    if 'HIDS' in section:
        H = HIDS()
        args = parser.options(section)
        for arg in args:
            if arg == 'name':
                H.name = parser.get(section, arg)
            if arg == 'version':
                H.version = parser.get(section, arg)
            if arg == 'accessright':
                H.accessRight = parser.get(section, arg)
            if arg == 'rules':
                H.rules = parser.get(section, arg)
        Services.append(H)

for section in parser.sections():
    if 'vuln' in section:
        V = Vulnerability()
        args = parser.options(section)
        for arg in args:
            if arg == 'name':
                V.name = parser.get(section, arg)
            if arg == 'software':
                V.software = parser.get(section, arg)
            if arg == 'trigger':
                V.trigger = parser.get(section, arg)
            if arg == 'action':
                V.action = parser.get(section, arg)
        Vulnerabilities.append(V)


for section in parser.sections():
    if 'Machine' in section:
        if 'Victim' in section:
            VM = Victim_Machine()
            args = parser.options(section)
            for arg in args:
                if arg == 'name':
                    VM.name = parser.get(section, arg)
                if arg == 'os':
                    VM.os = parser.get(section, arg)
                if arg == 'ip_address':
                    VM.IP_address = parser.get(section, arg)
                if arg == 'rights':
                    VM.rights = parser.get(section, arg)
                if arg == 'vulnerabilities':
                    L = []
                    VM_vulns = parser.get(section, arg).split(' ')
                    for vuln in Vulnerabilities:
                        for VM_vuln in VM_vulns:
                            if VM_vuln == vuln.name:
                                L.append(vuln)
                    VM.vulnerabilities = L
                if arg == 'booted':
                    VM.booted = parser.getboolean(section, arg)
                if arg == 'installed_software':
                    L = parser.get(section, arg).split(' ')
                    softwares = []
                    for software in Services:
                        for softwareName in L:
                            if software.name == softwareName:
                                softwares.append(software)
                        VM.setSoftwares(softwares)
                if arg == 'host-sonde':
                    for software in VM.installed_software:
                        if 'HIDS'in software.name:
                            VM.host_sonde = software
                if arg == 'subnet':
                    VM.subnet = parser.get(section, arg)  # affectation du nom, l'objet correspondant sera affecté après
            Victim_Machines.append(VM)

        if 'Attack' in section:
            AM = Attacking_Machine()
            args = parser.options(section)
            for arg in args:
                if arg == 'name':
                    AM.name = parser.get(section, arg)
                if arg == 'os':
                    AM.os = parser.get(section, arg)
                if arg == 'ip_address':
                    AM.IP_address = parser.get(section, arg)
                if arg == 'rights':
                    AM.rights = parser.get(section, arg)
                if arg == 'booted':
                    AM.booted = parser.getboolean(section, arg)
                if arg == 'installed_software':
                    L = parser.get(section, arg).split(' ')
                    softwares = []
                    for software in Services:
                        for softwareName in L:
                            if software.name == softwareName:
                                softwares.append(software)
                        AM.setSoftwares(softwares)
                if arg == 'host-sonde':
                    for software in VM.installed_software:
                        if 'HIDS'in software.name:
                            VM.host_sonde = software
                if arg == 'subnet':
                    VM.subnet = parser.get(section, arg)  # affectation du nom, l'objet correspondant sera affecté après
            Attack_Machines.append(AM)

        if 'Firewall' in section:
            FW = Firewall()
            args = parser.options(section)
            for arg in args:
                if arg == 'name':
                    FW.name = parser.get(section, arg)
                if arg == 'os':
                    FW.os = parser.get(section, arg)
                if arg == 'ip_address':
                    FW.IP_address = parser.get(section, arg)
                if arg == 'rights':
                    FW.rights = parser.get(section, arg)
                if arg == 'booted':
                    FW.booted = parser.getboolean(section, arg)
                if arg == 'installed_software':
                    L = parser.get(section, arg).split(' ')
                    softwares = []
                    for software in Services:
                        for softwareName in L:
                            if software.name == softwareName:
                                softwares.append(software)
                        FW.setSoftwares(softwares)
                if arg == 'host-sonde':
                    for software in VM.installed_software:
                        if 'HIDS'in software.name:
                            VM.host_sonde = software
                if arg == 'subnet':
                    FW.subnet = parser.get(section, arg)  # affectation du nom, l'objet correspondant sera affecté après
                if arg == 'rules':
                    Rules = parser.get(section, arg).split(',')
                    FW.setRules(Rules)
            Firewalls.append(FW)

        if 'Server' in section:
            SV = Server()
            args = parser.options(section)
            for arg in args:
                if arg == 'name':
                    SV.name = parser.get(section, arg)
                if arg == 'os':
                    SV.os = parser.get(section, arg)
                if arg == 'ip_address':
                    SV.IP_address = parser.get(section, arg)
                if arg == 'rights':
                    SV.rights = parser.get(section, arg)
                if arg == 'booted':
                    SV.booted = parser.getboolean(section, arg)
                if arg == 'installed_software':
                    L = parser.get(section, arg).split(' ')
                    softwares = []
                    for software in Services:
                        for softwareName in L:
                            if software.name == softwareName:
                                softwares.append(software)
                        SV.setSoftwares(softwares)
                if arg == 'host-sonde':
                    for software in VM.installed_software:
                        if 'HIDS'in software.name:
                            SV.host_sonde = software
                if arg == 'subnet':
                    SV.subnet = parser.get(section, arg)  # affectation du nom, l'objet correspondant sera affecté après
            Servers.append(SV)


for section in parser.sections():
    if 'subnet' in section:
        SB = Subnet()
        args = parser.options(section)
        for arg in args:
            if arg == 'name':
                SB.name = parser.get(section, arg)
            if arg == 'ip_range':
                SB.IP_range = parser.get(section, arg)
            if arg == 'components':
                L = []
                S_components = parser.get(section, arg).split(' ')
                for machine in Victim_Machines:
                    for S_component in S_components:
                        if S_component == machine.IP_address:
                            L.append(machine)
                for machine in Attack_Machines:
                    for S_component in S_components:
                        if S_component == machine.IP_address:
                            L.append(machine)
                SB.components = L
            if arg == 'router':
                SB.router = parser.get(section, arg)  # affectation du nom, l'objet correspondant sera affecté après
            if arg == 'sonde':
                SB.sonde = parser.get(section, arg)  # affectation du nom, l'objet correspondant sera affecté après
            if arg == 'firewall':
                for firewall in Firewalls:
                    if firewall.IP_address == parser.get(section, arg):
                        SB.firewall = firewall
        Subnets.append(SB)


for section in parser.sections():
    if 'sonde' in section:
        nids = NIDS()
        args = parser.options(section)
        for arg in args:
            if arg == 'name':
                nids.name = parser.get(section, arg)
            if arg == 'subnet':
                subnet_iprange = parser.get(section, arg)
                for subnet in Subnets:
                    if subnet.IP_range == subnet_iprange:
                        nids.setSubnet(subnet)
            if arg == 'rules':
                Rules = parser.get(section, arg).split(',')
                nids.setRules(Rules)
        Sondes.append(nids)


for section in parser.sections():
    if 'router' in section:
        RT = Router()
        args = parser.options(section)
        for arg in args:
            if arg == 'name':
                RT.name = parser.get(section, arg)
            if arg == 'subnetsin':
                L = []
                ins = parser.get(section, arg).split(' ')
                for subnet in Subnets:
                    for subnetip in ins:
                        if subnet.IP_range == subnetip:
                            L.append(subnet)
                RT.subnetsin = L

            if arg == 'subnetsout':
                L = []
                outs = parser.get(section, arg).split(' ')
                for subnet in Subnets:
                    for subnetip in outs:
                        if subnet.IP_range == subnetip:
                            L.append(subnet)
                RT.subnetsout = L
            if arg == 'gateway':
                RT.gateway = parser.getboolean(section, arg)
        Routers.append(RT)

Machines = Victim_Machines + Attack_Machines + Firewalls + Servers
for machine in Machines:
    for subnet in Subnets:
        if machine.subnet == subnet.IP_range:
            machine.setSubnet(subnet)

for subnet in Subnets:
    for router in Routers:
        if subnet.router == router.name:
            subnet.setRouter(router)
    for sonde in Sondes:
        if subnet.sonde == sonde.name:
            subnet.setSonde(sonde)
