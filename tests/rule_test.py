from filtergenerator import Rule


class TestRule:
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
