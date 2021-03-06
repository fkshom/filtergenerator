import sys
import io
import yaml
import ipaddress
import argparse
from pprint import pprint as pp
import re

class Router1():
    def __init__(self):
        self.interfaces = []
        self.rules = []
        self.repository = None

    def assign_interface(self, interfacename, filtername, address):
        self.interfaces.append(
            dict(interfacename=interfacename, filtername=filtername, address=address)
        )

    def set_repository(self, func):
        self.repository = func

    def add_rule(self, generate_return_rule=True, order_priority=50, **kwargs):
        self.rules.append((order_priority, kwargs))

    def _is_所属するIPアドレスからの通信を表すルール(self, interface_address, srcaddr):
        return ipaddress.IPv4Network(srcaddr).subnet_of(ipaddress.IPv4Interface(interface_address).network)

    def _resolve_addr(self, repository, addr_or_objectname):
        try:
            ipaddress.IPv4Interface(addr_or_objectname)
            return addr_or_objectname
        except ValueError:
            pass

        try:
            obj = repository.get_host_object(addr_or_objectname)
            return obj['ipaddress']
        except ValueError:
            raise Exception(f'objectname "{addr_or_objectname}" is not found in repository')

    def _resolve_port(self, repository, port_or_objectname):
        if re.fullmatch(r'\d+|\d+-\d+', port_or_objectname):
            return dict(protocol=None, port=port_or_objectname)
        
        try:
            obj = repository.get_port_object(port_or_objectname)
            return dict(protocol=obj['protocol'], port=obj['port'])
        except ValueError:
            Exception(f'objectname "{port_or_objectname} is not found in repository')

    def _prepare_protocol_and_ports_info(self, repository, protocol, srcport_or_objectname, dstport_or_objectname):
            srcport_info = self._resolve_port(self.repository, srcport_or_objectname)
            dstport_info = self._resolve_port(self.repository, dstport_or_objectname)

            # protocolの準備
            if srcport_info['protocol'] is not None and dstport_info['protocol'] is not None and srcport_info['protocol'] != dstport_info['protocol']:
                raise ValueError(f'srcport protocol "{srcport_info["protocol"]}" and dstport protocol "{dstport_info["protocol"]}" are different')

            protocol_candidate = srcport_info['protocol']
            
            if protocol_candidate is not None and protocol is not None:
                if protocol_candidate != protocol:
                    raise ValueError(f'srcport protocol "{protocol_candidate}" and protocol "{protocol}" are different')
                else:
                    return dict(protocol=protocol, srcport=srcport_info['port'], dstport=dstport_info['port'])
            elif protocol_candidate is not None and protocol is None:
                return dict(protocol=protocol_candidate, srcport=srcport_info['port'], dstport=dstport_info['port'])
            elif protocol_candidate is None and protocol is not None:
                return dict(protocol=protocol, srcport=srcport_info['port'], dstport=dstport_info['port'])
            elif protocol_candidate is None and protocol is None:
                raise ValueError(f'procotol is missing')
            else:
                raise Exception('Unknown Error Occured')

    def _generate_rule(self, **kwargs):
        pp(kwargs)
        result = []
        for interface in self.interfaces:
            srcaddr = self._resolve_addr(self.repository, kwargs['srcaddr'])
            dstaddr = self._resolve_addr(self.repository, kwargs['dstaddr'])
            tmp = self._prepare_protocol_and_ports_info(self.repository, kwargs.get('protocol'), kwargs.get('srcport'), kwargs.get('dstport'))
            protocol, srcport, dstport = tmp['protocol'], tmp['srcport'], tmp['dstport']

            if self._is_所属するIPアドレスからの通信を表すルール(interface['address'], srcaddr):
                interfacename = interface['filtername']
                termname = kwargs['name']

                result.append(
                    f"set firewall filter {interfacename} term {termname} source-address {srcaddr}"
                )
                result.append(
                    f"set firewall filter {interfacename} term {termname} destination-address {dstaddr}"
                )
                result.append(
                    f"set firewall filter {interfacename} term {termname} source-port {srcport}"
                )
                result.append(
                    f"set firewall filter {interfacename} term {termname} destination-port {dstport}"
                )
                result.append(
                    f"set firewall filter {interfacename} term {termname} protocol {protocol}"
                )
                result.append(
                    f"set firewall filter {interfacename} term {termname} {kwargs['action']}"
                )
        return result

    def create_filter_configuration(self):
        result = []
        for rule in self.rules:
            result.extend(self._generate_rule(**rule[1]))

        return result