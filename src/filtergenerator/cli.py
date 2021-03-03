import sys
import io
import yaml
import ipaddress
from pprint import pprint as pp

definition_yaml_text = """
HostObjects:
    DNSServer1: 10.0.1.50
    DNSServer2: 10.0.2.50
    MailServer_eth0: 10.0.3.10
    MailServer_eth1: 10.0.4.10
    ClientNW: 192.168.0.0/24

HostGroups:
    DNSServers:
    - DNSServer1
    - 10.0.1.51
    - DNSServer8
    - 10.0.2.51    

PortObjects:
    DefaultSourcePort1:
      protocol: [tcp, udp]
      port: 32765-65535
    udp53:
      protocol: udp
      port: 53
    tcp53:
      protocol: tcp
      port: 53

PortGroups:
    dns:
    - udp53 
    - { protoco: tcp, port: 53 }

rules:
    - name: ClientNWのインターネット接続用
      srcaddr: ClientNW
      srcport: DefaultSourcePort1
      dstaddr:
      - DNSServers
      - DNSServer1111
      dstport:
      - { protocol: tcp, port: 53 }
      - udp53
      action: permit
      return_rule: true
      order_priority: 50
"""

class Router1():
    def __init__(self):
        self.interfaces = []
        self.rules = []

    def assign_interface(self, interfacename, filtername, address):
        self.interfaces.append(
            dict(interfacename=interfacename, filtername=filtername, address=address)
        )

    def set_host_object_repository(self, func):
        self.host_object_repository = func

    def set_port_object_repository(self, func):
        self.port_object_repository = func

    def add_rule(self, generate_return_rule=True, order_priority=50, **kwargs):
        self.rules.append((order_priority, kwargs))

    def _generate_rule(self, **kwargs):
        pp(kwargs)
        result = []
        for interface in self.interfaces:
            # 当irbに入ってくるパケットに対するルール
            if ipaddress.IPv4Network(kwargs['srcaddr']).subnet_of(ipaddress.IPv4Interface(interface['address']).network):
                result.append(
                    f"set configuration firewall filter {interface['filtername']} term {kwargs['name']} source-address {kwargs['srcaddr']}"
                )

        # result = [
        #     "set configuration firewall filter irb100in term TERM1 source-address 1.1.1.1",
        #     "set configuration firewall filter irb100in term TERM1 source-port 32765-65535",
        #     "set configuration firewall filter irb100in term TERM1 destination-address 8.8.8.8",
        #     "set configuration firewall filter irb100in term TERM1 destination-port 53",
        #     "set configuration firewall filter irb100in term TERM1 protocol: udp",
        #     "set configuration firewall filter irb100in term TERM1 action accept",
        # ]
        # IPv4Network('192.168.0.2').subnet_of( IPv4Interface('192.168.0.1/24').network)
        return result

    def create_filter_configuration(self):
        result = []
        for rule in self.rules:
            result.extend(self._generate_rule(**rule[1]))

        return result


class VDS1():
    def __init__(self):
        self.networks = []
        self.rules = []

    def assign_network(self, address):
        self.networks.append(address)

    def add_rule(self, generate_return_rule=True, order_priority=50, **kwargs):
        self.rules.append((order_priority, kwargs))

    def _generate_rule(self, **kwargs):
        pp(kwargs)
        result = []
        for network in self.networks:
            pp(network)
            if ipaddress.IPv4Network(kwargs['srcaddr']).subnet_of(ipaddress.IPv4Network(network)):
                pp(True)
                result.append(
                    f"description: {kwargs['name']}, srcaddr: {kwargs['srcaddr']}"
                )
        return result

    def create_filter_configuration(self):
        result = []
        for rule in self.rules:
            result.extend(self._generate_rule(**rule[1]))
        return result

def main():
    definition_raw = yaml.safe_load(definition_yaml_text)
    # config = DefinitionRepository(config_raw)
    # config.rules
    # config.port_objects
    # config.host_objects
    # router1 = Router1()
    # for rule in config.rules:
    #     router1.add_rule(rule)

    def host_object_repository(object_name):
        objects = dict(
            DNSServer1='10.0.1.50',
            DNSServer2='10.0.2.50',
            DNSServers=['DNSServer1', '10.0.1.51', 'DNSServer2', '10.0.2.51'],
            ClientNW='192.168.0.0/24',
        )
        return objects.get(object_name)

    def port_object_repository(object_name):
        objects = dict(
            udp53=dict(protocol='udp', port='53'),
            DefaultSourcePort1='32765-65535',
        )
        return objects.get(object_name)

    router1 = Router1()
    router1.assign_interface(interfacename='irb100', filtername='irb100in', address="192.168.0.1/24")
    router1.set_host_object_repository(host_object_repository)
    router1.set_port_object_repository(port_object_repository)
    # router1.add_rule(
    #     srcaddr='ClientNW',
    #     srcport='DefaultSourcePort1',
    #     dstaddr=['DNSServers', 'DNSServer1'],
    #     dstport=[{'protocol':'tcp', 'port':'53'}, 'udp53'],
    #     action='permit',
    #     return_rule=True,
    #     order_priority=49,
    # )
    router1.add_rule(
        name='TERM1',
        srcaddr='192.168.0.0/24',
        srcport='32765-65535',
        dstaddr='10.0.1.50',
        protocol='udp',
        dstport='53',
        action='permit',
        generate_return_rule=True,
        order_priority=49,
    )
    pp(router1.create_filter_configuration(), width=150)

    vds1 = VDS1()
    vds1.assign_network(address="192.168.0.0/24")
    # vds1.set_host_object_repository(host_object_repository)
    # vds1.set_port_object_repository(port_object_repository)
    vds1.add_rule(
        name='TERM1',
        srcaddr='192.168.0.0/24',
        srcport='32765-65535',
        dstaddr='10.0.1.50',
        protocol='udp',
        dstport='53',
        action='permit',
        generate_return_rule=True,
        order_priority=49,
    )
    pp(vds1.create_filter_configuration(), width=150)

if __name__ == "__main__":
    main()
