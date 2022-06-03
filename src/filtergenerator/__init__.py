import csv
import ipaddress
import os
import argparse
from pprint import pp as pp
import glob

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
    headers = ['action', 'prot', 'srchost', 'srcip', 'srcport', 'dsthost', 'dstip', 'dstport']

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
        srcip = ipaddress.ip_network(rule['srcip'])
        dstip = ipaddress.ip_network(rule['dstip'])
        mysubnet = ipaddress.ip_network(self.mysubnet)
        if srcip.subnet_of(mysubnet) or dstip.subnet_of(mysubnet):
            return True
        return False

    def _gen_rule(self, rule):
        if not self.is_under_my_control(rule):
            return None

        return dict(
            desc="",
            **dict_slice(rule, ['action', 'prot', 'srcip', 'srcport', 'dstip', 'dstport'])
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

class VdsFilterOutputAnyAccept:
    def generate_rules_from(self, info, rules):
        myrules = []
        myrules.append(dict(
            action='accept',
            prot='any',
            srchost=info['mysubnet'],
            srcport='any',
            dsthost='0.0.0.0/0',
            dstport='any',
        ))
        for rule in rules:
            srcip = ipaddress.ip_network(rule['srcip'])
            mysubnet = ipaddress.ip_network(info['mysubnet'])
            if srcip.subnet_of(mysubnet):
                # 自分から外に出ているルールである
                continue
            else:
                myrules.append(rule)
        return myrules


def main(args=None):
    rules_header = ['action', 'prot', 'srchost', 'srcip', 'srcport', 'dsthost', 'dstip', 'dstport', 'direction']

    for rulefile in sorted(glob.glob("data/rules/*.csv")):
        with open(rulefile, 'r') as f:
            reader = csv.reader(f)
            rules = []
            for row in reader:
                stripped_row = map(lambda v: v.strip(), row)
                dicted_row = dict(zip(rules_header, stripped_row))
                excepted_row = dict_except(dicted_row, 'direction')
                rules.append(Rule(**excepted_row))

    vds = VdsFilterGenerator(mysubnet="10.0.10.0/24", flavors=[
        VdsFilterOutputAnyAccept(),
    ])
    vds_rules = vds.generate_rules_from(rules)
    # pp(vds_rules)

    router = RouterFilterGenerator(mysubnet="192.168.100.1/24", interfacename="irb100", direction="in", filtername="irb100in")
    router_rules = router.generate_rules_from(rules)
    pp(router_rules)


if __name__ == "__main__":
    main()
