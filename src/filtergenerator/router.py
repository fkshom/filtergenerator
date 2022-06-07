

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