import pytest
from assertpy import assert_that, fail
import yaml
import logging
import io
import textwrap
import tempfile
import subprocess
import os
import sys
from pprint import pprint as pp
from filtergenerator.repository import DefinitionRepository

logger = logging.getLogger(__name__)

definition_simple = textwrap.dedent("""
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
""")[1-1]
@pytest.fixture(scope='function', autouse=False)
def stdininlinevault(monkeypatch):
    monkeypatch.setattr('sys.stdin', io.StringIO(inlinevault))
    yield

@pytest.fixture(scope='function', autouse=False)
def definition_simple():
    passfile = 'tests/fixture/definition_simple.yml'
    with open(passfile, 'w') as f:
        print(passwords, end='', file=f)
    yield passfile

@pytest.fixture(scope='function', autouse=False)
def mock_decrypt_content_method():
    def _decrypt_content_mock(self, content, password):
        if content.strip() == wholevault.strip() and password == 'test':
            return wholevault_decrypted
        elif content.strip() == vaulted_data['item2'].replace(' ', '').strip() and password == 'test':
            return 'item2'
        elif content.strip() == vaulted_data['value2-2'].replace(' ', '').strip() and password == 'test':
            return 'value2-2'
        else:
            raise subprocess.CalledProcessError(returncode=1, cmd='ansible-vault')

    avault.AnsibleVault._decrypt_content_with_ansible_vault_command = _decrypt_content_mock
    yield

@pytest.fixture(scope='function', autouse=False)
def repository():
    repository = DefinitionRepository()
    yield repository

class TestDefinitionRepository():
    def test_オブジェクトとルールが追加できる(self, repository):
        repository.add_host_object(hostname='host1', ipaddress='192.168.0.1/24')
        repository.add_host_object(hostname='host2', ipaddress='10.0.0.1/24')
        repository.add_port_object(portname='udp53', protocol='udp', port=53)
        repository.add_port_object(portname='default_highport1', protocol='udp', port='32768-65535')
        repository.add_rule(
            name='Rule1',
            src='host1', srcport='default_highport1',
            dst='host2', dstport='udp53',
            generate_reverse_rule=True, action='accept'
        )
        assert_that(len(repository.host_objects)).is_equal_to(2)
        assert_that(len(repository.port_objects)).is_equal_to(2)
        assert_that(len(repository.rules)).is_equal_to(1) 

    def test_名前からオブジェクトを取得できる(self, repository):
        repository.add_host_object(hostname='host1', ipaddress='192.168.0.1/24')
        repository.add_host_object(hostname='host2', ipaddress='10.0.0.1/24')
        repository.add_port_object(portname='udp53', protocol='udp', port=53)
        repository.add_port_object(portname='default_highport1', protocol='udp', port='32768-65535')
        repository.add_rule(
            name='Rule1',
            src='host1', srcport='default_highport1',
            dst='host2', dstport='udp53',
            generate_reverse_rule=True, action='accept'
        )
        host_object = repository.get_host_object(hostname='host1', include_group=True)
        assert_that(host_object).is_equal_to(dict(hostname='host1', ipaddress='192.168.0.1/24'))
        port_object = repository.get_port_object(portname='udp53', include_group=True)
        assert_that(port_object).is_equal_to(dict(portname='udp53', protocol='udp', port=53))
