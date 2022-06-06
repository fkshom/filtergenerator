import csv
import ipaddress
import os
import argparse
from pprint import pp as pp
import glob

import yaml

def dict_slice(_dict, keys):
    result = {}
    for key in keys:
        result[key] = _dict.get(key, None)
    return result

def dict_except(_dict, keys):
    result = {}
    for key, value in _dict.items():
        if key not in keys:
            result[key] = value
    return result


class Rule:
    headers = ['desc', 'action', 'prot', 'srcip', 'srcport', 'dstip', 'dstport', 'comment']

    def __init__(self, *args, **kwargs):
        if args:
            self.rule = dict(zip(self.headers, args))
        elif kwargs:
            self.rule = kwargs
        else:
            raise Exception()

    def get(self, key, default):
        return self.rule.get(key, default)

    def __getattr__(self, name):
        if name in self.rule:
            return self.rule[name]

        raise AttributeError(f"{name}")

    def __getitem__(self, key):
        return self.rule[key]

    def __repr__(self):
        return self.rule.__repr__()

    def __str__(self):
        return self.rule.__str__()


class RouterFilterGenerator:
    def __init__(self, mysubnet, interfacename, direction, filtername, flavors=[]):
        self.mysubnet = mysubnet
        self.interfacename = interfacename
        self.direction = direction
        self.filtername = filtername
        self.flavors = flavors

    def is_under_my_control(self, rule):
        srcip = ipaddress.ip_network(rule['srcip'])
        dstip = ipaddress.ip_network(rule['dstip'])
        mysubnet = ipaddress.ip_network(self.mysubnet, strict=False)
        if srcip.subnet_of(mysubnet) or dstip.subnet_of(mysubnet):
            return True
        return False

    def _gen_rule(self, index, rule):
        if not self.is_under_my_control(rule):
            return None

        return dict(
            filtername=self.filtername,
            termname=f"term{index}",
            srcaddrs=[rule.srcip],
            dstaddrs=[rule.dstip],
            srcports=[rule.srcport],
            dstports=[rule.dstport],
            prot=rule['prot'],
            action=rule['action'],
        )

    def generate_rules_from(self, rules):
        myrules = []
        for index, rule in enumerate(rules):
            myrule = self._gen_rule(index, rule)
            if myrule:
                myrules.append(myrule)

        info = dict(
            mysubnet=self.mysubnet
        )
        for flavor in self.flavors:
            myrules = flavor.generate_rules_from(info, myrules)

        return myrules

class _RouterFilterSrcAggregator:
    def expand_rules(self, rules):
        myrules = []
        for rule in rules:
            for srcaddr in rule.srcaddrs:
                for dstaddr in rule.dstaddrs:
                    for srcport in rule.srcports:
                        for dstport in rule.dstports:
                            myrules.append(dict(
                                filtername=self.filtername,
                                termname=None,
                                srcaddr=srcaddr,
                                dstaddr=dstaddr,
                                srcport=srcport,
                                dstpot=dstport,
                                prot=rule.prot,
                                action=rule.action,
                            ))
        return myrules

    def generate_rules_from(self, info, rules):
        tmp = dict()
        for rule in self.expand_rules(rules):
            tmp.setdefault(rule['srcaddr'], [])
            tmp[ rule['srcaddr'] ].append(rule)

class VdsFilterGenerator:
    def __init__(self, mysubnet, flavors=[]):
        self.mysubnet = mysubnet
        self.flavors = flavors
        # anyルールは記載なし。

    def is_under_my_control(self, rule):
        if rule['srcip'].lower() == "any":
            srcip = ipaddress.ip_network("0.0.0.0/0")
        else:
            srcip = ipaddress.ip_network(rule['srcip'])
        if rule['dstip'].lower() == "any":
            dstip = ipaddress.ip_network("0.0.0.0/0")
        else:
            dstip = ipaddress.ip_network(rule['dstip'])

        mysubnet = ipaddress.ip_network(self.mysubnet)
        if srcip.subnet_of(mysubnet) or dstip.subnet_of(mysubnet):
            return True
        return False

    def _gen_rule(self, rule):
        if not self.is_under_my_control(rule):
            return None

        return Rule(
            **dict_slice(rule, ['desc', 'action', 'prot', 'srcip', 'srcport', 'dstip', 'dstport', 'comment'])
        )

    def generate_rules_from(self, rules):
        myrules = []
        for rule in rules:
            myrule = self._gen_rule(rule)
            if myrule:
                myrules.append(myrule)

        info = dict(
            mysubnet=self.mysubnet
        )
        for flavor in self.flavors:
            myrules = flavor.generate_rules_from(info, myrules)

        return myrules

class VdsFilterDenySameSubnet:
    def generate_rules_from(self, info, rules):
        myrules = rules
        myrules.append(Rule(
            desc='drop_mysubnet_mysubnet_any',
            action='drop',
            prot='any',
            srcip=info['mysubnet'],
            srcport='any',
            dstip=info['mysubnet'],
            dstport='any',
            comment='',
        ))
        return myrules

class VdsFilterOutputAnyAccept:
    def generate_rules_from(self, info, rules):
        myrules = []
        for rule in rules:
            srcip = ipaddress.ip_network(rule['srcip'])
            mysubnet = ipaddress.ip_network(info['mysubnet'])
            if rule['action'] == 'accept' and srcip.subnet_of(mysubnet):
                # 自分から外に出ているルールである
                continue
            else:
                myrules.append(rule)
        myrules.append(Rule(
            desc='permit_mysubnet_int_any',
            action='accept',
            prot='any',
            srcip=info['mysubnet'],
            srcport='any',
            dstip='0.0.0.0/0',
            dstport='any',
            comment='',
        ))

        return myrules

def split_desctiption(desc):
    return desc.split("_")

def main(args=None):
    rules_header = ['desc', 'drop', 'prot', 'srcip', 'srcport', 'dstip', 'dstport', 'comment']

    for rulefile in sorted(glob.glob("data/rules/*.csv")):
        with open(rulefile, 'r') as f:
            reader = csv.reader(f)
            rules = []
            for row in reader:
                stripped_row = map(lambda v: v.strip(), row)
                dicted_row = dict(zip(rules_header, stripped_row))
                action, srchost, dsthost, prot = split_desctiption(dicted_row['desc'])
                dicted_row['action'] = 'accept' if dicted_row['drop'] == "" else "drop"
                excepted_row = dicted_row
                rules.append(Rule(**excepted_row))

    with open("data/interfaces.yml", 'r') as f:
        interface_config = yaml.safe_load(f)

    # 順番が大切
    candidate_flavors = [
        ("VdsFilterDenySameSubnet", VdsFilterDenySameSubnet),
        ("VdsFilterOutputAnyAccept", VdsFilterOutputAnyAccept),
    ]

    for vds in interface_config['vdses']:
        dcpg_name = f"{vds['dcname']}_{vds['pgname']}"
        mysubnet = vds['address']
        print(dcpg_name, f"({mysubnet})")
        flavors = []
        for flavor_name, flavor_class in candidate_flavors:
            if vds['flavors'].get(flavor_name, False) == True:
                flavors.append(flavor_class())

        vds = VdsFilterGenerator(mysubnet=mysubnet, flavors=flavors)
        vds_rules = vds.generate_rules_from(rules)
        pp(vds_rules)

    # router = RouterFilterGenerator(mysubnet="192.168.100.1/24", interfacename="irb100", direction="in", filtername="irb100in")
    # router_rules = router.generate_rules_from(rules)
    # pp(router_rules)


if __name__ == "__main__":
    main()
