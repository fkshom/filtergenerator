import copy
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


class RuleBase:
    def __init__(self, *args, **kwargs):
        if args:
            stripped_row = map(lambda v: v.strip(), args)
            dicted_row = dict(zip(self.headers, stripped_row))
            tmp = split_desctiption(dicted_row['desc'])
            if len(tmp) == 4:
                action, srchost, dsthost, prot, ret = [*tmp, None]
            elif len(tmp) == 5:
                action, srchost, dsthost, prot, ret = tmp
            else:
                raise Exception()

            dicted_row['action'] = 'accept' if dicted_row['action'] == "" else "drop"
            dicted_row['srcip'] = dicted_row['srcip'].replace("!", "")
            dicted_row['dstip'] = dicted_row['dstip'].replace("!", "")
            self.rule = dicted_row
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


class AggregatedRule(RuleBase):
    headers = ['desc', 'action', 'prot', 'srcip', 'srcport', 'dstip', 'dstport', 'direction', 'prio', 'comment']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def expand(self):
        ret = []
        if self.rule['direction'] in ['', 'both']:
            tmp = copy.copy(self.rule)
            tmp = dict_except(tmp, ['direction'])
            ret.append(Rule(**tmp))
            tmp = copy.copy(self.rule)
            tmp = dict_except(tmp, ['direction'])
            tmp['srcip'], tmp['dstip'] = tmp['dstip'], tmp['srcip']
            tmp['srcport'], tmp['dstport'] = tmp['dstport'], tmp['srcport']
            tmp['desc'] = tmp['desc'] + "_RET"
            ret.append(Rule(**tmp))
        elif self.rule['direction'] in ['fwd']:
            tmp = copy.copy(self.rule)
            tmp = dict_except(tmp, ['direction'])
            ret.append(Rule(**tmp))
        else:
            pp(self.rule)
            raise Exception()
        return ret

class Rule(RuleBase):
    headers = ['desc', 'action', 'prot', 'srcip', 'srcport', 'dstip', 'dstport', 'prio', 'comment']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class UniversalRules:
    def load(self, filenames):
        for rulefile in filenames:
            with open(rulefile, 'r') as f:
                reader = csv.reader(f)
                rules = []
                for row in reader:
                    rules.append(AggregatedRule(*row))
        self._rules = rules

    @property
    def rules(self):
        ret = []
        for rule in self._rules:
            ret.extend(rule.expand())
        return ret

class VdsFilterGenerator:
    def __init__(self, mysubnet, flavors=[]):
        self.mysubnet = mysubnet
        self.flavors = flavors
        # anyルールは記載なし。

    def is_under_my_control(self, rule):
        if rule['srcip'].lower() == "any":
            srcip = ipaddress.ip_network("0.0.0.0/0")
        else:
            try:
                srcip = ipaddress.ip_network(rule['srcip'])
            except:
                pp(rule)
                raise

        if rule['dstip'].lower() == "any":
            dstip = ipaddress.ip_network("0.0.0.0/0")
        else:
            try:
                dstip = ipaddress.ip_network(rule['dstip'])
            except:
                pp(rule)
                raise

        mysubnet = ipaddress.ip_network(self.mysubnet)
        if srcip.subnet_of(mysubnet) or dstip.subnet_of(mysubnet):
            return True
        return False

    def generate_rules_from(self, rules):
        myrules = []
        for rule in rules:
            if self.is_under_my_control(rule):
                myrules.append(rule)

        info = dict(
            mysubnet=self.mysubnet,
            flavors=self.flavors,
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
            prio='90',
            comment='',
        ))
        return myrules

class VdsFilterOutputAnyAccept:
    def generate_rules_from(self, info, rules):
        myrules = []
        if VdsFilterDenySameSubnet not in info['flavors']:
            # OUTPUTAnyAcceptが許可されており、同セグ通信が許可されているなら、自分から外に出るルールは削除してよい
            for rule in rules:
                srcip = ipaddress.ip_network(rule['srcip'])
                mysubnet = ipaddress.ip_network(info['mysubnet'])
                if rule['action'] == 'accept' and srcip.subnet_of(mysubnet):
                    # 自分から外に出ているルールである
                    continue
                else:
                    myrules.append(rule)
        else:
            # OUTPUTAnyAcceptが許可されているが、同セグ通信が禁止されているなら、自分から自分にでるルール以外は削除してよい
            for rule in rules:
                srcip = ipaddress.ip_network(rule['srcip'])
                dstip = ipaddress.ip_network(rule['dstip'])
                mysubnet = ipaddress.ip_network(info['mysubnet'])
                if rule['action'] == 'accept':
                    if srcip.subnet_of(mysubnet) and dstip.subnet_of(mysubnet):
                        # 自分から自分にいくルールである
                        myrules.append(rule)
                    elif srcip.subnet_of(mysubnet) and not dstip.subnet_of(mysubnet):
                        # 自分から外に行くルールである
                        continue

        myrules.append(Rule(
            desc='permit_mysubnet_int_any',
            action='accept',
            prot='any',
            srcip=info['mysubnet'],
            srcport='any',
            dstip='0.0.0.0/0',
            dstport='any',
            prio='90',
            comment='',
        ))

        return myrules

class _VdsFilterCleanup:
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

        return rules

def split_desctiption(desc):
    return desc.split("_")

def main(args=None):
    univ_rules = UniversalRules()
    filenames = sorted(glob.glob("data/rules/*.csv"))
    univ_rules.load(filenames=filenames)
    rules = univ_rules.rules

    with open("data/interfaces.yml", 'r') as f:
        interface_config = yaml.safe_load(f)

    # 順番が大切
    candidate_flavors = [
        ("VdsFilterDenySameSubnet", VdsFilterDenySameSubnet),
        ("VdsFilterOutputAnyAccept", VdsFilterOutputAnyAccept),
        # ("VdsFilterCleanup", VdsFilterCleanup)
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
        # TODO: OutputAnyAcceptで、同セグ通信も消されてしまう


if __name__ == "__main__":
    main()
