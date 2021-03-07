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
            return dict(protocol=obj.get('protocol'), port=obj['port'])
        except ValueError:
            raise Exception(f'objectname "{port_or_objectname} is not found in repository')

    def _prepare_protocol_and_ports_info(self, repository, protocol, srcport_or_objectname, dstport_or_objectname):
        srcport_info = self._resolve_port(repository, srcport_or_objectname)
        dstport_info = self._resolve_port(repository, dstport_or_objectname)

        protocol_candidate = dstport_info.get('protocol')
        protocol_conclusive = None

        if protocol_candidate is not None and protocol is not None:
            if srcport_info.get('protocol') != protocol:
                raise ValueError(f'srcport protocol "{protocol_candidate}" and protocol "{protocol}" are different')
            else:
                protocol_conclusive = protocol
        elif protocol_candidate is not None and protocol is None:
            protocol_conclusive = protocol_candidate
        elif protocol_candidate is None and protocol is not None:
            protocol_conclusive = protocol
        elif protocol_candidate is None and protocol is None:
            raise ValueError(f'procotol is missing')
        else:
            raise Exception('Unknown Error Occured')

        return dict(protocol=protocol_conclusive, srcport=srcport_info['port'], dstport=dstport_info['port'])

    # インタフェースごとにルールを展開する
    def _preexpand_rule(self, **kwargs):
        import itertools
        result = []
        srcaddrs = list(itertools.chain.from_iterable([kwargs['srcaddr']]))
        for interface in self.interfaces:
            srcaddrs1 = []
            for srcaddr in srcaddrs:
                srcaddr1 = self._resolve_addr(self.repository, srcaddr)
                if self._is_所属するIPアドレスからの通信を表すルール(interface['address'], srcaddr1):
                    srcaddrs1.append(srcaddr)

            if len(srcaddrs1) > 0:
                result.append(dict(
                    name=kwargs['name'],
                    srcaddr=srcaddrs1,
                    srcport=kwargs['srcport'],
                    dstaddr=kwargs['dstaddr'],
                    dstport=kwargs['dstport'],
                    action=kwargs['action'],
                ))

        return result

    def _generate_rule_old2(self, **kwargs):
        result = []
        # TODO: INルールのみ作成できるのでOUTも作成できるようにする

        srcaddrs = []
        if type(kwargs['srcaddr']) is list:
            srcaddrs = kwargs['srcaddr']
        else:
            srcaddrs = [kwargs['srcaddr']]

        dstaddrs = []
        if type(kwargs['dstaddr']) is list:
            dstaddrs = kwargs['dstaddr']
        else:
            dstaddrs = [kwargs['dstaddr']]

        srcports = []
        if type(kwargs['srcport']) is list:
            srcports = kwargs['srcport']
        else:
            srcports = [kwargs['srcport']]

        dstports = []
        if type(kwargs['dstport']) is list:
            dstports = kwargs['dstport']
        else:
            dstports = [kwargs['dstport']]

        for interface in self.interfaces:
            # srcaddrsから、インタフェース所属のもののみ抽出
            interfacename = interface['filtername']
            termname = kwargs['name']

            for dstport in dstports:
                pp(dstport)
                cnt = 0
                for srcaddr in srcaddrs:
                    srcaddr1 = self._resolve_addr(self.repository, srcaddr)
                    if self._is_所属するIPアドレスからの通信を表すルール(interface['address'], srcaddr1):
                        result.append(f"set firewall filter {interfacename} term {termname} source-address {srcaddr1}")
                        cnt += 1
                if cnt == 0:
                    next
                
                for dstaddr in dstaddrs:
                    dstaddr1 = self._resolve_addr(self.repository, dstaddr)
                    result.append(f"set firewall filter {interfacename} term {termname} destination-address {dstaddr1}")

                for srcport in srcports:
                    tmp = self._prepare_protocol_and_ports_info(self.repository, kwargs.get('protocol'), srcport, dstport)
                    protocol, srcport1, dstport1 = tmp['protocol'], tmp['srcport'], tmp['dstport']
                    result.append(f"set firewall filter {interfacename} term {termname} source-port {srcport1}")

                result.append(f"set firewall filter {interfacename} term {termname} destination-port {dstport1}")
                result.append(f"set firewall filter {interfacename} term {termname} protocol {protocol}")
                result.append(f"set firewall filter {interfacename} term {termname} {kwargs['action']}")


        return result

    def _generate_rule(self, **kwargs):
        result = []

        srcaddr = self._resolve_addr(self.repository, kwargs['srcaddr'])
        dstaddr = self._resolve_addr(self.repository, kwargs['dstaddr'])
        tmp = self._prepare_protocol_and_ports_info(self.repository, kwargs.get('protocol'), kwargs.get('srcport'), kwargs.get('dstport'))
        protocol, srcport, dstport = tmp['protocol'], tmp['srcport'], tmp['dstport']

        for interface in self.interfaces:
            
            if self._is_所属するIPアドレスからの通信を表すルール(interface['address'], srcaddr):
                interfacename = interface['filtername']
                termname = kwargs['name']

                result.append(f"set firewall filter {interfacename} term {termname} source-address {srcaddr}")
                result.append(f"set firewall filter {interfacename} term {termname} destination-address {dstaddr}")
                result.append(f"set firewall filter {interfacename} term {termname} source-port {srcport}")
                result.append(f"set firewall filter {interfacename} term {termname} destination-port {dstport}")
                result.append(f"set firewall filter {interfacename} term {termname} protocol {protocol}")
                result.append(f"set firewall filter {interfacename} term {termname} {kwargs['action']}")

        return result

    def create_filter_configuration(self):
        result = []
        for rule in self.rules:
            ret = self._generate_rule(**rule[1])
            result.extend(ret)

        return result