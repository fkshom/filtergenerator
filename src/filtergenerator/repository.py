
class DefinitionRepository():
    def __init__(self):
        self.host_objects = []
        self.port_objects = []
        self.rules = []

    def add_host_object(self, **kwargs):
        self.host_objects.append(dict(
            hostname=kwargs['hostname'],
            ipaddress=kwargs['ipaddress']
        ))

    def add_port_object(self, **kwargs):
        self.port_objects.append(dict(
            portname=kwargs['portname'],
            protocol=kwargs.get('protocol'),
            port=kwargs['port']
        ))
    
    def add_rule(self, **kwargs):
        self.rules.append(dict(
            name=kwargs['name'],
            src=kwargs['src'], srcport=kwargs['srcport'],
            dst=kwargs['dst'], dstport=kwargs['dstport'],
            generate_reverse_rule=kwargs['generate_reverse_rule'], action=kwargs['action']
        ))
    
    def get_host_object(self, hostname, include_group=True):
        for host_object in self.host_objects:
            if hostname == host_object['hostname']:
                return host_object
        raise ValueError()

    def get_port_object(self, portname, include_group=True):
        for port_object in self.port_objects:
            if portname == port_object['portname']:
                return port_object
        raise ValueError()

    def expand_object(self, objectname):
        pass
        
