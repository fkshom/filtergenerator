import sys
import io
import yaml
import ipaddress
import argparse
from pprint import pprint as pp
from .repository import DefinitionRepository





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

def gen_simple_repository():
    repository = DefinitionRepository()
    repository.add_host_object(hostname='host1', )

def command_genvds(args):
    repository = DefinitionRepository()
    pass

def command_genrouter(args):
    repository = DefinitionRepository()
    pass

def main(args=None):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    
    parser_view = subparsers.add_parser('genrouter')
    parser_view.add_argument('filename', nargs='?', default='-')
    parser_view.set_defaults(handler=command_genrouter)

    args = parser.parse_args(args)
    if hasattr(args, 'handler'):
        return args.handler(args)
    else:
        return parser.print_help()

    # definition_raw = yaml.safe_load(definition_yaml_text)
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
