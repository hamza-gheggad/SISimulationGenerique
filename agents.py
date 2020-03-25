import logging


class Software:
    def __init__(self, name='NULL', version='NULL', accessRight="user", password=""):
        self.name = name
        self.version = version
        self.accessRight = accessRight
        self.password = password

    def start(self):
        pass

    def exit(self):
        pass

    def root_only(self):
        if self.accessRight == "user":
            self.accessRight = "root"
            logging.debug("Les droits d'accès pour {} sont désormais root.".format(self.name))
        else:
            print("Les droits d'accès sont déjà root only.")

    def any_user(self):
        if self.accessRight == "root":
            self.accessRight = "user"
            logging.debug("Les droits d'accès pour {} sont désormais user.".format(self.name))
        else:
            print("Les droits d'accès sont déjà user (any).")


class Router:
    def __init__(self, name='NULL', subnetsin=[], subnetsout=[]):
        self.name = name
        self.subnetsin = subnetsin
        self.subnetsout = subnetsout
        self.gateway = True

    def endRouting(self):
        if self.gateway == True:
            self.gateway = False
            logging.debug("Le routeur {} <-> {} est arrêté.".format(self.subnetsin, self.subnetsout))
        else:
            print("Ce routeur est déjà arrêté.")

    def restartRouting(self):
        if self.gateway == False:
            self.gateway = True
            logging.debug("Le routeur {} <-> {}est démarré.".format(self.subnetsin, self.subnetsout))
        else:
            print("Ce routeur est déjà démarré.")


class Subnet:
    def __init__(self, name="NULL", sonde="NULL", IP_range='0.0.0.0/24', components=[], router="NULL", firewall='NULL'):
        self.name = name
        self.components = components
        self.sonde = sonde
        self.router = router
        self.firewall = firewall
        self.IP_range = IP_range

    def add_node(self, node):
        self.components.append(node)
        logging.debug("Le noeud {} a été ajouté au sous-réseau {}.".format(node.name, self.name))

    def remove_node(self, node):
        self.components.remove(node)
        logging.debug("Le noeud {} a été supprimé du sous-réseau {}.".format(node.name, self.name))

    def setRouter(self, router):
        self.router = router

    def setSonde(self, sonde):
        self.sonde = sonde


class File_System:
    def __init__(self, Repositories=[], Files=[]):
        self.Repositories = Repositories
        self.Files = Files


class Vulnerability:
    def __init__(self, name="NULL", software=Software(), trigger="NULL", action="NULL"):
        self.name = name
        self.software = software
        self.trigger = trigger
        self.action = action


class Machine:
    def __init__(self, name='NULL', os='NULL', IP_address='NULL', installed_software=[], rights='user', subnet=Subnet(), filesystem=File_System(), booted=False, host_sonde=Software()):
        self.name = name
        self.booted = booted
        self.os = os
        self.rights = rights
        self.IP_address = IP_address
        self.installed_software = installed_software
        self.subnet = subnet
        self.host_sonde = host_sonde
        self.filesystem = filesystem

    def boot(self):
        if self.booted == False:
            self.booted = True
            logging.debug("La machine {} a été démarrée.".format(self.name))
        else:
            print("La machine est déjà démarrée.")

    def shutdown(self):
        if self.booted == True:
            self.booted = False
            logging.debug("La machine {} a été arretée.".format(self.name))
        else:
            print("La machine est déjà arretée.")

    def reboot(self):
        if self.booted == True:
            logging.debug("La machine {} a été redémarrée.".format(self.name))
        else:
            print("La machine est déjà arretée.")

    def to_root(self):
        if self.rights == 'user':
            self.rights = 'root'
            logging.debug("Les droits sur la machine {} sont désormais root.".format(self.name))
        else:
            print("Vous êtes déjà root")

    def to_user(self):
        if self.rights == 'root':
            self.rights = 'user'
            logging.debug("Les droits sur la machine {} sont désormais user.".format(self.name))
        else:
            print("Vous êtes déjà user")

    def addSoftware(self, software):
        self.installed_software.append(software)

    def removeSoftware(self, software):
        self.installed_software.remove(software)

    def setSoftwares(self, softwares):
        self.installed_software = softwares

    def setSubnet(self, subnet):
        self.subnet = subnet


class Victim_Machine(Machine):
    def __init__(self, name='NULL', os='NULL', IP_address='NULL', installed_software=[], rights='user', vulnerabilities=[], defense_actions=[], subnet=Subnet(), filesystem=File_System([], []), booted=False, host_sonde=Software()):
        self.name = name
        self.os = os
        self.IP_address = IP_address
        self.rights = rights
        self.installed_software = installed_software
        self.vulnerabilities = vulnerabilities
        self.defense_actions = defense_actions
        self.subnet = subnet
        self.filesystem = filesystem
        self.host_sonde = host_sonde
        self.booted = booted


class Attacking_Machine(Machine):
    def __init__(self, name='NULL', os='NULL', IP_address='NULL', installed_software='NULL', rights='user', attack_actions=[], subnet=Subnet(), filesystem=File_System(), booted=False, host_sonde=Software()):
        self.name = name
        self.os = os
        self.IP_address = IP_address
        self.rights = rights
        self.installed_software = installed_software
        self.attack_actions = attack_actions
        self.subnet = subnet
        self.filesystem = filesystem
        self.host_sonde = host_sonde
        self.booted = booted


class Firewall(Machine):
    def __init__(self, name="NULL", os="NULL", IP_address="NULL", installed_software=[], vulnerabilities=[], rights='user', rules=[], subnet=Subnet(), filesystem=File_System(), booted=False, host_sonde=Software()):
        self.name = name
        self.os = os
        self.IP_address = IP_address
        self.rights = rights
        self.installed_software = installed_software
        self.rules = rules
        self.subnet = subnet
        self.vulnerabilities = vulnerabilities
        self.filesystem = filesystem
        self.host_sonde = host_sonde
        self.booted = booted

    def addRule(self, rule):
        self.rules.append(rule)
        logging.debug("La règle <{}> est ajoutée au parfeu de {}.".format(rule, self.name))

    def removeRule(self, rule):
        self.rules.remove(rule)
        logging.debug("La règle <{}> est ajoutée au parfeu de {}.".format(rule, self.name))

    def setRules(self, rules):
        self.rules = rules


class Server(Victim_Machine):
    def __init__(self, name='NULL', os='NULL', IP_address='NULL', vulnerabilities=[], installed_software=[], rights='user', subnet=Subnet(), booted=False, host_sonde=Software()):
        self.name = name
        self.os = os
        self.subnet = subnet
        self.IP_address = IP_address
        self.rights = rights
        self.installed_software = installed_software
        self.host_sonde = host_sonde
        self.booted = booted


class User:
    def __init__(self, name='NULL', machine=Machine()):
        self.name = name
        self.machine = machine

    def connect_to(self, machine):
        print("{} est connecté à {}.".format(self.name, machine.name))


class Victime(User):
    def __init__(self, name='NULL', VictimMachine=Machine()):
        self.name = name
        self.VictimMachine = VictimMachine

    def defend(self):
        pass


class Attaquant(User):
    def __init__(self, name='NULL', AttackingMachine=Machine()):
        self.name = name
        self.AttackingMachine = AttackingMachine

    def execAttack(self, attaque, DestinationMachine):
        logging.debug("L'attaque {} est exécutée sur {}.".format(attaque, DestinationMachine))


class HIDS(Software):
    def __init__(self, name='NULL', version="NULL", accessRight="user", rules="NULL"):
        self.name = name
        self.version = version
        self.rules = rules
        self.accessRight = accessRight

    def alert(self, message="NULL"):
        print('alerte HIDS : {}'.format(message))
        logging.debug("alerte HIDS : {}".format(message))


class NIDS:
    def __init__(self, name="NULL", subnet=Subnet(), rules=[]):
        self.name = name
        self.subnet = subnet
        self.rules = rules

    def setSubnet(self, subnet):
        self.subnet = subnet

    def addRule(self, rule):
        self.rules.append(rule)

    def removeRule(self, rule):
        self.rules.remove(rule)

    def setRules(self, rules):
        self.rules = rules

    def alert(self, message="NULL"):
        print('alerte : {}'.format(message))
        logging.debug("alerte NIDS du sous-réseau {}:{} : {}".format(self.subnet.name, self.subnet.IP_range, message))
