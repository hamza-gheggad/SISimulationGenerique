import simpy
import time
import logging
logging.basicConfig(filename="scenario.log", level=logging.DEBUG, format='%(asctime)s:%(message)s')

from agents import *
from instances import *


def exploit(L, machine):
    for subnet in Subnets:
        for node in subnet.components:
            if node.IP_address == L[2]:
                access = True
                rules = subnet.firewall.rules
                for rule in rules:
                    Rule = rule.split()
                    if "i" in Rule[1] and Rule[2] == 'NETCAT' and Rule[3] == 'REJECT' and Rule[4] == machine.subnet.IP_range:
                        print("Exploit bloqué par firewall.")
                        access = False

                if access == True:
                    for software in node.installed_software:
                        time.sleep(1)
                        if software.name == L[1]:
                            for vuln in node.vulnerabilities:
                                print(vuln.software, software.name)
                                if vuln.software == software.name:
                                    print("action : {}".format(vuln.action))
                                    node.rights = software.accessRight
                                    logging.debug("Les droits sur la machine {} sont : {}".format(node.name, node.rights))
                                    if vuln.software == 'Guacamole':
                                        new_password = input('new password: ')
                                        for software in node.installed_software:
                                            if "SSH" in software.name:
                                                software.password = new_password

        if (subnet.sonde != "NULL"):
            rules = subnet.sonde.rules
            for rule in rules:
                if 'DETECT DISTANT EXPLOIT' in rule:
                    subnet.sonde.alert("La machine  {}  du sous-réseau {} est en train d'être exploitée.".format(node.IP_address, subnet.IP_range))


def whoami(L, machine):
    if len(L) == 1:
        print(machine.rights)
    else:
        for subnet in Subnets:
            for node in subnet.components:
                if node.IP_address == L[1]:
                    if node.booted == True:
                        print(node.rights)
                    else:
                        print("{} est arrêtée.".format(node.IP_address))


def scan_services(L):
    H = []
    for subnet in Subnets:
        for node in subnet.components:
            if node.IP_address == L[1]:
                if (node.host_sonde.name != "NULL"):
                    rules = node.host_sonde.rules.split(',')
                    for rule in rules:
                        if 'DETECT SERVICE SCAN' in rule:
                            node.host_sonde.alert("Scan détecté! les services de la machine {} sont en train d'être scannés.".format(node.name))
                else:
                    for software in node.installed_software:
                        time.sleep(1)
                        print(software.name)
                        H.append(software.name)

    logging.debug("La liste des softwares pour la machine {} trouvée est : {}".format(L[1], H))


def scan_machines(L):
    H = []
    for subnet in Subnets:
        if subnet.IP_range == L[2]:
            if ("s" in L[1]):
                time.sleep(2)
                for node in subnet.components:
                    print("{}:{}".format(node.name, node.IP_address))
                    H.append(node.name)
            if 'f' in L[1]:
                for node in subnet.components:
                    print("{}:{}".format(node.name, node.IP_address))
                    H.append(node.name)
                rules = subnet.sonde.rules
                if (subnet.sonde != "NULL"):
                    for rule in rules:
                        if 'DETECT FAST SCAN' in rule:
                            subnet.sonde.alert("le sous-réseau {} est en train d'être scanné.".format(subnet.IP_range))

    logging.debug("Les machines du sous-réseau {} sont {}".format(subnet.IP_range, H))


def main():
    for user in Users:
        if user.name == 'Anonymous':
            attaquant = user

    env = simpy.Environment()
    env.process(scenario(env, attaquant=attaquant, speed=2))
    env.run(until=100)


def scenario(env, attaquant, speed):

    while True:

        try:
            x = input("{}> ".format(attaquant.name))
            L = x.split()

            if ('help' in L) or ('h' in L):
                print("\nLes commandes disponibles sont :\n\nlist_subnet_machines -> lister toutes les machines de votre subnet.\n\nscan_services <ip_machine> -> lister les services ouverts sur machine.\n\nget_version <software> <ip_machine> -> récupérer la version du logiciel.\n\nwhoami <ip> -> afficher les droits\n\nip <machine_name> -> ip de machine.\n\nos <ip_machine> -> os de machine.\n\nhelp ou h -> afficher ce menu\n\nexit ou q -> pour quitter.\n\nboot/shutdown/reboot <ip> -> démarrer/arrêter/redémarrer machine.\n\nroot <software> <ip_machine> -> changer les droits à root.\n\nuser <software> <ip_machine> -> changer les droits à user.\n\nrouter -i/o -> point de départ/d'arrivée du routeur\n\nscan_machines -s/f <subnet_IP_range> -> lister les machines d'un réseau.\n\nssh username@ip_address\n\nexploit <software_name> <ip>")

            if 'list_subnet_machines' in L:
                H = []
                for node in attaquant.machine.subnet.components:
                    time.sleep(1)
                    yield env.timeout(speed)
                    print("{}:{}".format(node.name, node.IP_address))
                    H.append((node.name, node.IP_address))

                logging.debug("Les machines ayant le même sous-réseau que {} sont {}".format(attaquant.machine.IP_address, H))

            if 'router' in L:
                if "i" in L[1]:
                    for subnet in attaquant.machine.subnet.router.subnetsin:
                        print(subnet.IP_range)
                if "o" in L[1]:
                    for subnet in attaquant.machine.subnet.router.subnetsout:
                        print(subnet.IP_range)

            if 'ssh' in L and '@' in L[1]:
                for subnet in Subnets:
                    for machine in subnet.components:
                        for software in machine.installed_software:
                            if 'SSH' in software.name:
                                if machine.IP_address in L[1] and machine.name in L[1] and machine.booted == True:
                                    password = input("password:")
                                    if software.password == password:
                                        print("Mot de passe correct")
                                        rules = subnet.firewall.rules
                                        print("Essai de connexion ssh à {}...".format(machine.IP_address))
                                        time.sleep(3)
                                        yield env.timeout(speed)
                                        access = True
                                        if subnet.firewall.name != 'NULL':
                                            for rule in rules:
                                                L = rule.split()
                                                if ("i" in L[1] and L[2] == 'SSH' and L[3] == 'REJECT' and L[4] == attaquant.machine.subnet.IP_range):
                                                    access = False
                                                    print('Connexion bloquée par firewall.')
                                                else:
                                                    access = True

                                        if access == True:
                                            print("Connexion ssh réussie à {}".format(machine.IP_address))
                                            while True:
                                                shell_ssh = input("{}$".format(machine.name))
                                                H = shell_ssh.split()
                                                if ('exit' in H) or ('q' in H):
                                                    break
                                                if 'reboot' in H:
                                                    machine.reboot()
                                                if 'shutdown' in H:
                                                    machine.shutdown()
                                                    break
                                                if 'exploit' in H:
                                                    exploit(H, machine)
                                                if 'router' in H:
                                                    if "i" in H[1]:
                                                        for subnet in machine.subnet.router.subnetsin:
                                                            print(subnet.IP_range)
                                                    if "o" in H[1]:
                                                        for subnet in machine.subnet.router.subnetsout:
                                                            print(subnet.IP_range)
                                                if 'firewall' in H and (machine.name != "NULL"):
                                                    if H[1] == 'delete' and H[3] == 'rule':
                                                        if H[2] == 'NETCAT':
                                                            for rule in machine.rules:
                                                                if 'NETCAT' in rule:
                                                                    machine.removeRule(rule)

                                                    else:
                                                        print("un argument qui manque à votre commande. Voir <help>.")
                                                if 'scan_machines' in H:  # découvrir les machines sur un sous-réseau
                                                    scan_machines(H)
                                                if 'whoami' in H:
                                                    whoami(H, machine)

                                                if 'scan_services' in H:
                                                    scan_services(H)

                                                if 'list_subnet_machines' in H:
                                                    for node in machine.subnet.components:
                                                        time.sleep(1)
                                                        yield env.timeout(speed)
                                                        print("{}:{}".format(node.name, node.IP_address))

                                                if 'ssh' in H[0] and '@' in H[1]:
                                                    for submachine in machine.subnet.components:
                                                        if submachine.IP_address in H[1] and submachine.name in H[1] and submachine.booted == True:
                                                            for subsoftware in submachine.installed_software:
                                                                if 'SSH' in subsoftware.name:
                                                                    password = input("password:")
                                                                    if subsoftware.password == password:
                                                                        print("Connexion ssh réussie à {}".format(submachine.IP_address))
                                                                        while True:
                                                                            subshell_ssh = input("{}$".format(submachine.name))
                                                                            S = subshell_ssh.split()
                                                                            if ('exit' in S) or ('q' in S):
                                                                                break
                                                                            if 'shutdown' in S:
                                                                                submachine.shutdown()
                                                                                break
                                                                            if 'reboot' in S:
                                                                                submachine.reboot()
                                                                            if 'whoami' in S:
                                                                                whoami(S, submachine)
                                                                            if 'scan_services' in S:
                                                                                scan_services(S)
                                                                            if 'exploit' in S:
                                                                                exploit(S, submachine)
                                                                            if 'router' in S:
                                                                                if "i" in S[1]:
                                                                                    for subnet in submachine.subnet.router.subnetsin:
                                                                                        print(subnet.IP_range)
                                                                                if "o" in H[1]:
                                                                                    for subnet in submachine.subnet.router.subnetsout:
                                                                                        print(subnet.IP_range)
                                                                    else:
                                                                        print("mot de passe érroné. Connexion ssh non permise.")

                                    else:
                                        print("mot de passe érroné. Connexion ssh non permise.")

            if 'scan_services' in L:
                yield env.timeout(speed)
                scan_services(L)

            if 'exploit' in L:
                yield env.timeout(speed)
                exploit(L, attaquant.machine)

            if 'root' in L:  # rendre root les droits sur un software
                for node in attaquant.machine.subnet.components:
                    if node.IP_address == L[2]:
                        if node.rights == 'root':
                            for software in node.installed_software:
                                if software.name == L[1]:
                                    time.sleep(1)
                                    yield env.timeout(speed)
                                    software.root_only()
                        else:
                            print("Vous n'avez pas les droits nécessaires.")

            if 'user' in L:  # rendre user les droits sur un software
                for node in attaquant.machine.subnet.components:
                    if node.IP_address == L[2]:
                        if node.rights == 'root':
                            for software in node.installed_software:
                                if software.name == L[1]:
                                    time.sleep(1)
                                    yield env.timeout(speed)
                                    software.any_user()
                        else:
                            print("Vous n'avez pas les droits nécessaires.")

            if 'scan_machines' in L:  # découvrir les machines sur un sous-réseau
                yield env.timeout(speed)
                scan_machines(L)

            if 'get_version' in L:
                for node in attaquant.machine.subnet.components:
                    if node.IP_address == L[2]:
                        for software in node.installed_software:
                            if software.name == L[1]:
                                time.sleep(1)
                                yield env.timeout(speed)
                                print(software.version)
                                logging.debug("La version de {} de {} est : {}".format(software.name, node.name, software.version))

            if 'ip' in L:
                if len(L) == 1:
                    print(attaquant.machine.IP_address)
                else:
                    for node in attaquant.machine.subnet.components:
                        if node.name == L[1]:
                            time.sleep(1)
                            yield env.timeout(speed)
                            print(node.IP_address)
                            logging.debug("ip de {} est : {}".format(node.name, node.IP_address))

            if 'os' in L:
                if len(L) == 1:
                    yield env.timeout(speed)
                    print(attaquant.machine.os)
                else:
                    for node in attaquant.machine.subnet.components:
                        if node.IP_address == L[1]:
                            time.sleep(1)
                            yield env.timeout(speed)
                            print(node.os)
                            logging.debug("os de {} est : {}".format(node.name, node.os))

            if 'whoami' in L:
                whoami(L, attaquant.machine)

            if 'shutdown' in L:
                if len(L) == 1:
                    yield env.timeout(speed)
                    print(attaquant.machine.shutdown())
                    break
                else:
                    for subnet in Subnets:
                        for node in subnet.components:
                            if node.IP_address == L[1]:
                                if node.rights == 'root':
                                    yield env.timeout(speed)
                                    node.shutdown()
                                else:
                                    print("Vous n'avez pas les droits nécessaires.")
            if 'reboot' in L:
                if len(L) == 1:
                    yield env.timeout(speed)
                    print(attaquant.machine.reboot())
                    break
                else:
                    for subnet in Subnets:
                        for node in subnet.components:
                            if node.IP_address == L[1]:
                                if node.rights == 'root':
                                    node.reboot()
                                else:
                                    print("Vous n'avez pas les droits nécessaires.")
            if ('exit' in L) or ('q' in L):
                break
                exit()

        except (IndexError, ValueError):
            print("Commande non reconnue, consultez le manuel avec la commande <help>.")


if __name__ == "__main__":
    main()
