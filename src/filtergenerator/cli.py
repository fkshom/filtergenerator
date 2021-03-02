import sys
import io
import yaml
import ipaddress
from pprint import pprint as pp

config_yaml_text = """
host_objects:
    DNSServer1: 10.0.1.50
    DNSServer2: 10.0.2.50
    DNSServers:
    - DNSServer1
    - 10.0.1.51
    - DNSServer8
    - 10.0.2.51
    MailServer_eth0: 10.0.3.10
    MailServer_eth1: 10.0.4.10
    ClientNW:
    - 192.168.0.0/24

port_objects:
    - DefaultSourcePort1:
      protocol: [tcp, udp]
      port: 30000-65535
    - udp53:
      protocol: udp
      port: 53

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
        self.interface_addresses = []
        self.rules = []

    def assign_interface_address(self, interfacename, filtername, address):
        self.interface_addresses.append(
            dict(interfacename=interfacename, filtername=filtername, address=address)
        )

    def set_host_object_repository(self, func):
        self.host_object_repository = func

    def set_port_object_repository(self, func):
        self.port_object_repository = func

    def add_rule(self, return_rule=True, order_priority=50, **kwargs):
        self.rules.append((order_priority, kwargs))

    def _generate_rule(self, **kwargs):
        result = [
            "set configuration firewall filter irb100in term TERM1 source-address 1.1.1.1",
            "set configuration firewall filter irb100in term TERM1 source-port 30000-65535",
            "set configuration firewall filter irb100in term TERM1 destination-address 8.8.8.8",
            "set configuration firewall filter irb100in term TERM1 destination-port 53",
            "set configuration firewall filter irb100in term TERM1 protocol: udp",
            "set configuration firewall filter irb100in term TERM1 action accept",
        ]
        return result

    def create_filter_configuration(self):
        result = []
        for rule in self.rules:
            result.extend(self._generate_rule(**rule[1]))

        return result

def main():
    config_raw = yaml.safe_load(config_yaml_text)
    # config = Config(config_raw)
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
        )
        return objects.get(object_name)

    router1 = Router1()
    router1.assign_interface_address(interfacename='irb100', filtername='irb100in', address="192.168.0.1/24")
    router1.set_host_object_repository(host_object_repository)
    router1.set_port_object_repository(port_object_repository)
    router1.add_rule(
        srcaddr='ClientNW',
        srcport='DefaultSourcePort1',
        dstaddr=['DNSServers', 'DNSServer1'],
        dstport=[{'protocol':'tcp', 'port':'53'}, 'udp53'],
        action='permit',
        return_rule=True,
        order_priority=49,
    )

    pp(router1.create_filter_configuration(), width=150)

if __name__ == "__main__":
    main()
