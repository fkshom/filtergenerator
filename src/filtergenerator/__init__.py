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
            tmp = split_description(dicted_row['desc'])
            if len(tmp) == 4:
                action, srchost, dsthost, prot, ret = [*tmp, None]
            elif len(tmp) == 5:
                action, srchost, dsthost, prot, ret = tmp
            else:
                raise Exception()

            dicted_row['action'] = 'accept' if dicted_row['action'] == "" else "drop"
            self.rule = dicted_row
        elif kwargs:
            self.rule = kwargs
        else:
            raise Exception()

    def get(self, key, default):
        return self.rule.get(key, default)

    def is_outgoing_from(self, subnet):
        srcip = ipaddress.ip_network(self.srcip)
        dstip = ipaddress.ip_network(self.dstip)
        subnet = ipaddress.ip_network(subnet)

        if not self.is_srcip_neg() and (srcip.subnet_of(subnet) or subnet.subnet_of(srcip)):
            return True
        elif self.is_srcip_neg() and not (srcip.subnet_of(subnet) or subnet.subnet_of(srcip)):
            return True
        else:
            return False

    def is_incoming_from(self, subnet):
        srcip = ipaddress.ip_network(self.srcip)
        dstip = ipaddress.ip_network(self.dstip)
        subnet = ipaddress.ip_network(subnet)

        if not self.is_dstip_neg() and (dstip.subnet_of(subnet) or subnet.subnet_of(dstip)):
            return True
        elif self.is_dstip_neg() and not (dstip.subnet_of(subnet) or subnet.subnet_of(dstip)):
            return True
        else:
            return False

    def is_nothing_from(self, subnet):
        if not self.is_outgoing_from(subnet) and not self.is_incoming_from(subnet):
            return True
        else:
            return False

    def is_same_from(self, subnet):
        if self.is_outgoing_from(subnet) and self.is_incoming_from(subnet):
            return True
        else:
            return False

    @property
    def srcip(self):
        srcip = self.rule['srcip'].replace("!", "")
        if srcip.lower() == 'any':
            return "0.0.0.0/0"
        else:
            return srcip

    @property
    def dstip(self):
        dstip = self.rule['dstip'].replace("!", "")
        if dstip.lower() == 'any':
            return "0.0.0.0/0"
        else:
            return dstip

    def is_srcip_neg(self):
        if self.rule['srcip'].startswith("!"):
            return True
        else:
            return False

    def is_dstip_neg(self):
        if self.rule['dstip'].startswith("!"):
            return True
        else:
            return False

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
        if self.rule['direction'] in ['', 'bi']:
            tmp = copy.copy(self.rule)
            tmp = dict_except(tmp, ['direction'])
            ret.append(Rule(**tmp))
            tmp = copy.copy(self.rule)
            tmp = dict_except(tmp, ['direction'])
            tmp['srcip'], tmp['dstip'] = tmp['dstip'], tmp['srcip']
            tmp['srcport'], tmp['dstport'] = tmp['dstport'], tmp['srcport']
            tmp['desc'] = tmp['desc'] + "_RET"
            ret.append(Rule(**tmp))
        elif self.rule['direction'] in ['uni']:
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
        self._flavors = flavors
        self.flavors = [flavor_class() for flavor_class in self._flavors]

    def is_under_my_control(self, rule):
        if rule.is_outgoing_from(self.mysubnet) or rule.is_incoming_from(self.mysubnet):
            return True
        else:
            return False

    def generate_rules_from(self, rules):
        myrules = []

        # 自分のPGに関係あるルールを抽出
        for rule in rules:
            if self.is_under_my_control(rule):
                myrules.append(rule)

        # フレーバー処理
        info = dict(
            mysubnet=self.mysubnet,
            flavors=self._flavors,
        )
        for flavor in self.flavors:
            myrules = flavor.generate_rules_from(info, myrules)

        # ソート
        myrules2 = sorted(myrules, key=lambda x: x['action'], reverse=True)
        myrules2 = sorted(myrules2, key=lambda x: x['prio'])

        return myrules2

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
        myrules = rules
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

class VdsFilterCleanup:
    def generate_rules_from(self, info, rules):
        myrules = []
        mysubnet = info['mysubnet']
        if VdsFilterDenySameSubnet in info['flavors']:
            # OUTPUTAnyAcceptが許可されているが、同セグ通信が禁止されているなら、自分から自分にでるルール以外は削除してよい
            for rule in rules:
                if rule.is_same_from(mysubnet) or rule.is_incoming_from(mysubnet):
                    # 同セグ通信である か 自分に入ってくるルールである
                    myrules.append(rule)
                elif rule.is_outgoing_from(mysubnet):
                    # 自分から外に行くルールである
                    continue
        else:
            # OUTPUTAnyAcceptが許可されており、同セグ通信が許可されているなら、自分から外に出るルールは削除してよい
            for rule in rules:
                if rule.is_outgoing_from(mysubnet):
                    continue
                else:
                    myrules.append(rule)

        return myrules

def split_description(desc):
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
        ("VdsFilterCleanup", VdsFilterCleanup),
        ("VdsFilterDenySameSubnet", VdsFilterDenySameSubnet),
        ("VdsFilterOutputAnyAccept", VdsFilterOutputAnyAccept),
    ]

    for vds in interface_config['vdses']:
        dcpg_name = f"{vds['vcentername']}_{vds['dcname']}_{vds['pgname']}"
        mysubnet = vds['address']
        print(dcpg_name, f"({mysubnet})")
        flavors = []
        for flavor_name, flavor_class in candidate_flavors:
            if vds['flavors'].get(flavor_name, False) == True:
                flavors.append(flavor_class)

        vds = VdsFilterGenerator(mysubnet=mysubnet, flavors=flavors)
        vds_rules = vds.generate_rules_from(rules)
        pp(vds_rules)




if __name__ == "__main__":
    main()
