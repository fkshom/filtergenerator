import pytest
from assertpy import assert_that, fail
import yaml
import logging
from filtergenerator.routers import Router1
from filtergenerator.repository import DefinitionRepository
import io
import textwrap
import tempfile
import subprocess
import os
import sys
from pprint import pprint as pp

class TestRouter1():
    def test_シングルルールからfilterを生成できる(self):
        router = Router1()
        router.assign_interface(interfacename='irb100', filtername='irb100in', address="192.168.0.1/24")
        router.add_rule(
            name='TERM1',
            srcaddr='192.168.0.0/24',
            srcport='32768-65535',
            dstaddr='10.0.1.50/32',
            protocol='udp',
            dstport='53',
            action='accept',
            generate_return_rule=True,
            order_priority=49,
        )
        actual = router.create_filter_configuration()
        expect = [
            "set firewall filter irb100in term TERM1 source-address 192.168.0.0/24",
            "set firewall filter irb100in term TERM1 destination-address 10.0.1.50/32",
            "set firewall filter irb100in term TERM1 source-port 32768-65535",
            "set firewall filter irb100in term TERM1 destination-port 53",
            "set firewall filter irb100in term TERM1 protocol udp",
            "set firewall filter irb100in term TERM1 accept",
        ]
        pp(expect)
        pp(actual)
        assert_that(actual).is_equal_to(expect)

    def test_オブジェクト名を使用したシングルルールからfilterを生成できる(self):
        repository = DefinitionRepository()
        repository.add_host_object(hostname='network1', ipaddress='192.168.0.0/24')
        repository.add_host_object(hostname='host2', ipaddress='10.0.1.50/32')
        repository.add_port_object(portname='udp53', protocol='udp', port=53)
        repository.add_port_object(portname='default_highport1', port='32768-65535')

        router = Router1()
        router.assign_interface(interfacename='irb100', filtername='irb100in', address='192.168.0.1/24')
        router.set_repository(repository)
        router.add_rule(
            name='TERM1',
            srcaddr='network1',
            srcport='default_highport1',
            dstaddr='host2',
            dstport='udp53',
            action='accept',
            generate_return_rule=True,
            order_priority=49,
        )
        actual = router.create_filter_configuration()
        expect = [
            "set firewall filter irb100in term TERM1 source-address 192.168.0.0/24",
            "set firewall filter irb100in term TERM1 destination-address 10.0.1.50/32",
            "set firewall filter irb100in term TERM1 source-port 32768-65535",
            "set firewall filter irb100in term TERM1 destination-port 53",
            "set firewall filter irb100in term TERM1 protocol udp",
            "set firewall filter irb100in term TERM1 accept",
        ]
        pp(expect)
        pp(actual)
        assert_that(actual).is_equal_to(expect)

    def test_preexpand_rule(self):
        repository = DefinitionRepository()
        repository.add_host_object(hostname='srcnetwork1', ipaddress='192.168.0.0/24')
        repository.add_host_object(hostname='srcnetwork2', ipaddress='192.168.1.0/24')
        repository.add_host_object(hostname='host1', ipaddress='10.0.1.50/32')
        repository.add_host_object(hostname='host2', ipaddress='10.0.1.51/32')
        repository.add_port_object(portname='udp53', protocol='udp', port=53)
        repository.add_port_object(portname='tcp53', protocol='tcp', port=53)
        repository.add_port_object(portname='default_highport1', port='32768-65535')
        repository.add_port_object(portname='default_highport2', port='50000-65535')

        router = Router1()
        router.assign_interface(interfacename='irb100', filtername='irb100in', address='192.168.0.1/24')
        router.assign_interface(interfacename='irb110', filtername='irb110in', address='192.168.1.1/24')
        router.set_repository(repository)

        param = dict(
            name='TERM1',
            srcaddr=['srcnetwork1', 'srcnetwork2'],
            srcport=['default_highport1', 'default_highport2'],
            dstaddr=['host1', 'host2'],
            dstport=['udp53'],
            action='accept',
            generate_return_rule=True,
            order_priority=49,
        )
        actual = router._preexpand_rule(**param)
        expect = [dict(
            name='TERM1',
            srcaddr=['srcnetwork1'],
            srcport=['default_highport1', 'default_highport2'],
            dstaddr=['host1', 'host2'],
            dstport=['udp53'],
            action='accept',
        ),
        dict(
            name='TERM1',
            srcaddr=['srcnetwork2'],
            srcport=['default_highport1', 'default_highport2'],
            dstaddr=['host1', 'host2'],
            dstport=['udp53'],
            action='accept',
        )]
        pp(expect)
        pp(actual)
        assert_that(actual).is_equal_to(expect)

    @pytest.mark.skip()
    def test_オブジェクト名を使用したマルチタームルールからfilterを生成できる(self):
        repository = DefinitionRepository()
        repository.add_host_object(hostname='srchost1', ipaddress='192.168.0.0/24')
        repository.add_host_object(hostname='srcnetwork1', ipaddress='192.168.0.1/32')
        repository.add_host_object(hostname='host1', ipaddress='10.0.1.50/32')
        repository.add_host_object(hostname='host2', ipaddress='10.0.1.51/32')
        repository.add_port_object(portname='udp53', protocol='udp', port=53)
        repository.add_port_object(portname='tcp53', protocol='tcp', port=53)
        repository.add_port_object(portname='default_highport1', port='32768-65535')
        repository.add_port_object(portname='default_highport2', port='50000-65535')

        router = Router1()
        router.assign_interface(interfacename='irb100', filtername='irb100in', address='192.168.0.1/24')
        router.assign_interface(interfacename='irb110', filtername='irb110in', address='192.168.1.1/24')
        router.set_repository(repository)
        router.add_rule(
            name='TERM1',
            srcaddr=['srchost1', 'srcnetwork1'],
            srcport=['default_highport1', 'default_highport2'],
            dstaddr=['host1', 'host2'],
            dstport=['udp53'],
            action='accept',
            generate_return_rule=True,
            order_priority=49,
        )
        actual = router.create_filter_configuration()
        expect = [
            "set firewall filter irb100in term TERM1 source-address 192.168.0.0/24",
            "set firewall filter irb100in term TERM1 source-address 192.168.0.1/32",
            "set firewall filter irb100in term TERM1 destination-address 10.0.1.50/32",
            "set firewall filter irb100in term TERM1 destination-address 10.0.1.51/32",
            "set firewall filter irb100in term TERM1 source-port 32768-65535",
            "set firewall filter irb100in term TERM1 source-port 50000-65535",
            "set firewall filter irb100in term TERM1 destination-port 53",
            "set firewall filter irb100in term TERM1 protocol udp",
            "set firewall filter irb100in term TERM1 accept",
        ]
        pp(expect)
        pp(actual)
        assert_that(actual).is_equal_to(expect)

    @pytest.mark.skip()
    def test_オブジェクト名を使用した複雑なマルチタームルールからfilterを生成できる(self):
        repository = DefinitionRepository()
        repository.add_host_object(hostname='network1', ipaddress='192.168.0.0/24')
        repository.add_host_object(hostname='network2', ipaddress='192.168.1.0/24')
        repository.add_host_object(hostname='host1', ipaddress='10.0.1.50/32')
        repository.add_host_object(hostname='host2', ipaddress='10.0.1.51/32')
        repository.add_port_object(portname='udp53', protocol='udp', port=53)
        repository.add_port_object(portname='tcp53', protocol='tcp', port=53)
        repository.add_port_object(portname='default_udp_highport1', protocol='udp', port='32768-65535')
        repository.add_port_object(portname='default_udp_highport2', protocol='udp', port='50000-65535')

        router = Router1()
        router.assign_interface(interfacename='irb100', filtername='irb100in', address='192.168.0.1/24')
        router.assign_interface(interfacename='irb110', filtername='irb110in', address='192.168.1.1/24')
        router.set_repository(repository)
        router.add_rule(
            name='TERM1',
            srcaddr=['network1', 'network2'],
            srcport=['default_udp_highport1', 'default_udp_highport2'],
            dstaddr=['host1', 'host2'],
            dstport=['udp53'],  # srcportのプロトコルと異なるプロトコルは指定できない
            action='accept',
            generate_return_rule=True,
            order_priority=49,
        )
        # TODO: プロトコルが複数指定できるかを確認する
        actual = router.create_filter_configuration()
        expect = [
            "set firewall filter irb100in term TERM1 source-address 192.168.0.0/24",
            "set firewall filter irb100in term TERM1 destination-address 10.0.1.50/32",
            "set firewall filter irb100in term TERM1 destination-address 10.0.1.51/32",
            "set firewall filter irb100in term TERM1 source-port 32768-65535",
            "set firewall filter irb100in term TERM1 source-port 50000-65535",
            "set firewall filter irb100in term TERM1 destination-port 53",
            "set firewall filter irb100in term TERM1 protocol tcp",
            "set firewall filter irb100in term TERM1 accept",
            
            "set firewall filter irb100in term TERM1 source-address 192.168.1.0/24",
            "set firewall filter irb100in term TERM1 destination-address 10.0.1.50/32",
            "set firewall filter irb100in term TERM1 destination-address 10.0.1.51/32",
            "set firewall filter irb100in term TERM1 source-port 32768-65535",
            "set firewall filter irb100in term TERM1 source-port 50000-65535",
            "set firewall filter irb100in term TERM1 destination-port 53",
            "set firewall filter irb100in term TERM1 protocol udp",
            "set firewall filter irb100in term TERM1 accept",

            "set firewall filter irb110in term TERM1 source-address 192.168.0.0/32",
            "set firewall filter irb110in term TERM1 destination-address 10.0.1.50/32",
            "set firewall filter irb110in term TERM1 destination-address 10.0.1.51/32",
            "set firewall filter irb110in term TERM1 source-port 32768-65535",
            "set firewall filter irb110in term TERM1 source-port 50000-65535",
            "set firewall filter irb110in term TERM1 destination-port 53",
            "set firewall filter irb110in term TERM1 protocol udp",
            "set firewall filter irb110in term TERM1 accept",

            "set firewall filter irb110in term TERM1 source-address 192.168.1.0/32",
            "set firewall filter irb110in term TERM1 destination-address 10.0.1.50/32",
            "set firewall filter irb110in term TERM1 destination-address 10.0.1.51/32",
            "set firewall filter irb110in term TERM1 source-port 32768-65535",
            "set firewall filter irb110in term TERM1 source-port 50000-65535",
            "set firewall filter irb110in term TERM1 destination-port 53",
            "set firewall filter irb110in term TERM1 protocol udp",
            "set firewall filter irb110in term TERM1 accept",
        ]
        pp(expect)
        pp(actual)
        assert_that(actual).is_equal_to(expect)