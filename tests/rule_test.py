from filtergenerator import Rule, merge_rules


class TestRule:
    def testx1(self):
        assert Rule(
            action='',
            prot='TCP',
            srcip="192.168.0.1/32",
            srcport='any',
            dstip="10.0.0.0/24",
            dstport=80,
        ).contains(
        Rule(
            action='',
            prot='TCP',
            srcip="192.168.0.1/32",
            srcport='any',
            dstip="10.0.0.1/32",
            dstport=80,
        )) == True

    def testx2(self):
        rules = []
        rules.append(Rule(
            action='', prot='TCP', srcip="192.168.0.1/32", srcport='any', dstip="10.0.0.1/32", dstport=80,
        ))
        rules.append(Rule(
            action='', prot='TCP', srcip="192.168.0.1/32", srcport='any', dstip="10.0.0.2/32", dstport=80,
        ))
        rules.append(Rule(
            action='', prot='TCP', srcip="192.168.0.1/32", srcport='any', dstip="10.0.0.0/24", dstport=80,
        ))
        rules.append(Rule(
            action='', prot='TCP', srcip="192.168.0.1/32", srcport='any', dstip="10.0.0.2/32", dstport=81,
        ))
        rules.append(Rule(
            action='', prot='TCP', srcip="192.168.0.1/32", srcport='any', dstip="10.0.0.4/32", dstport=80,
        ))
        rules.append(Rule(
            action='', prot='TCP', srcip="192.168.0.1/32", srcport='any', dstip="10.0.0.5/32", dstport=80,
        ))
        actual = merge_rules(rules)
        assert len(actual) == 2

    def test1(self):
        rule = Rule(
            srcip="192.168.0.1/32",
            dstip="10.0.0.1/32",
        )
        assert rule.is_srcip_neg() == False
        assert rule.is_dstip_neg() == False

        rule = Rule(
            srcip="!192.168.0.1/32",
            dstip="!10.0.0.1/32",
        )
        assert rule.is_srcip_neg() == True
        assert rule.is_dstip_neg() == True

    def test2(self):
        rule = Rule(
            srcip="192.168.0.0/24",
            dstip="10.0.0.1/32",
        )
        assert rule.is_outgoing_from("192.168.0.1/32") == True
        assert rule.is_outgoing_from("10.0.0.1/32") == False
        assert rule.is_outgoing_from("172.16.0.1/32") == False
        assert rule.is_incoming_from("192.168.0.1/32") == False
        assert rule.is_incoming_from("10.0.0.1/32") == True
        assert rule.is_incoming_from("172.16.0.1/32") == False
        assert rule.is_same_from("192.168.0.1/32") == False
        assert rule.is_same_from("10.0.0.1/32") == False
        assert rule.is_same_from("172.16.0.1/32") == False
        assert rule.is_nothing_from("192.168.0.1/32") == False
        assert rule.is_nothing_from("10.0.0.1/32") == False
        assert rule.is_nothing_from("172.16.0.1/32") == True

        rule = Rule(
            srcip="192.168.0.1/32",
            dstip="10.0.0.0/24",
        )
        assert rule.is_outgoing_from("192.168.0.1/32") == True
        assert rule.is_outgoing_from("10.0.0.1/32") == False
        assert rule.is_outgoing_from("172.16.0.1/32") == False
        assert rule.is_incoming_from("192.168.0.1/32") == False
        assert rule.is_incoming_from("10.0.0.1/32") == True
        assert rule.is_incoming_from("172.16.0.1/32") == False
        assert rule.is_same_from("192.168.0.1/32") == False
        assert rule.is_same_from("10.0.0.1/32") == False
        assert rule.is_same_from("172.16.0.1/32") == False
        assert rule.is_nothing_from("192.168.0.1/32") == False
        assert rule.is_nothing_from("10.0.0.1/32") == False
        assert rule.is_nothing_from("172.16.0.1/32") == True

    def test3(self):
        rule = Rule(
            srcip="192.168.0.1/32",
            dstip="10.0.0.1/32",
        )
        assert rule.is_outgoing_from("192.168.0.0/24") == True
        assert rule.is_outgoing_from("10.0.0.0/24") == False
        assert rule.is_outgoing_from("172.16.0.0/24") == False
        assert rule.is_incoming_from("192.168.0.0/24") == False
        assert rule.is_incoming_from("10.0.0.0/24") == True
        assert rule.is_incoming_from("172.16.0.0/24") == False
        assert rule.is_same_from("192.168.0.0/24") == False
        assert rule.is_same_from("10.0.0.0/24") == False
        assert rule.is_same_from("172.16.0.0/24") == False
        assert rule.is_nothing_from("192.168.0.0/24") == False
        assert rule.is_nothing_from("10.0.0.0/24") == False
        assert rule.is_nothing_from("172.16.0.0/24") == True

        rule = Rule(
            srcip="192.168.0.1/32",
            dstip="192.168.0.2/32",
        )
        assert rule.is_outgoing_from("192.168.0.0/24") == True
        assert rule.is_outgoing_from("10.0.0.0/24") == False
        assert rule.is_outgoing_from("172.16.0.0/24") == False
        assert rule.is_incoming_from("192.168.0.0/24") == True
        assert rule.is_incoming_from("10.0.0.0/24") == False
        assert rule.is_incoming_from("172.16.0.0/24") == False
        assert rule.is_same_from("192.168.0.0/24") == True
        assert rule.is_same_from("10.0.0.0/24") == False
        assert rule.is_same_from("172.16.0.0/24") == False
        assert rule.is_nothing_from("192.168.0.0/24") == False
        assert rule.is_nothing_from("10.0.0.0/24") == True
        assert rule.is_nothing_from("172.16.0.0/24") == True

        rule = Rule(
            srcip="192.168.0.1/32",
            dstip="!10.0.0.0/24",
        )
        assert rule.is_outgoing_from("192.168.0.0/24") == True
        assert rule.is_outgoing_from("10.0.0.0/24") == False
        assert rule.is_outgoing_from("172.16.0.0/24") == False
        assert rule.is_incoming_from("192.168.0.0/24") == True
        assert rule.is_incoming_from("10.0.0.0/24") == False
        assert rule.is_incoming_from("172.16.0.0/24") == True
        assert rule.is_same_from("192.168.0.0/24") == True
        assert rule.is_same_from("10.0.0.0/24") == False
        assert rule.is_same_from("172.16.0.0/24") == False
        assert rule.is_nothing_from("192.168.0.0/24") == False
        assert rule.is_nothing_from("10.0.0.0/24") == True
        assert rule.is_nothing_from("172.16.0.0/24") == False

        rule = Rule(
            srcip="!192.168.0.0/24",
            dstip="10.0.0.1/32",
        )
        assert rule.is_outgoing_from("192.168.0.0/24") == False
        assert rule.is_outgoing_from("10.0.0.0/24") == True
        assert rule.is_outgoing_from("172.16.0.0/24") == True
        assert rule.is_incoming_from("192.168.0.0/24") == False
        assert rule.is_incoming_from("10.0.0.0/24") == True
        assert rule.is_incoming_from("172.16.0.0/24") == False
        assert rule.is_same_from("192.168.0.0/24") == False
        assert rule.is_same_from("10.0.0.0/24") == True
        assert rule.is_same_from("172.16.0.0/24") == False
        assert rule.is_nothing_from("192.168.0.0/24") == True
        assert rule.is_nothing_from("10.0.0.0/24") == False
        assert rule.is_nothing_from("172.16.0.0/24") == False
