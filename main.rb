require 'yaml'
require_relative "lib/filtergen/filtergen"
def main()

  s_interfaces =<<~EOS
  router1:
    - interfacename: irb100
      filtername: irb100in
      direction: in
      address: 192.168.0.1/24
    - interfacename: irb110
      filtername: irb110in
      direction: in
      address: 192.168.1.1/24
  EOS
  
  s_definitions =<<~EOS
  hostObject:
  - hostname: network0
    address: 192.168.0.0/24
  - hostname: network1
    address: 192.168.1.0/24
  - hostname: host0
    address: 10.0.1.50/32
  - hostname: host1
    address: 10.0.1.51/32
  
  portObject:
  - portname: udp53
    protocol: udp
    port: 53
  - portname: default_highport1
    port: 32768-65535
  
  rule:
  - name: TERM1
    src: ['network0', 'network1']
    dst: ['host0', 'host1']
    srcport: default_highport1
    dstport: udp53
    action: accept
  EOS

  l_interfaces = YAML.load(s_interfaces)
  l_definitions = YAML.load(s_definitions)

  repository = Filtergen::Repository.new()
  (l_definitions['hostObject'] || []).each do |host_object|
    repository.add_host_object(hostname: host_object['hostname'], address: host_object['address'])
  end
  (l_definitions['portObject'] || []).each do |port_object|
    repository.add_port_object(portname: port_object['portname'], protocol: port_object['protocol'], port: port_object['port'])
  end
  
  router = Filtergen::Routers::Router1.new()
  router.set_repository(repository)

  (l_interfaces['router1'] || []).each do |interface|
    router.assign_interface(interfacename: interface['interfacename'], filtername: interface['filtername'],
      direction: interface['direction'], address: interface['address'])
  end

  (l_definitions['portObject'] || []).each do |port_object|
    repository.add_port_object(portname: port_object['portname'], protocol: port_object['protocol'], port: port_object['port'])
  router.add_rule(
    name: 'TERM1',
    src: ['network0', 'network1'],
    srcport: '32768-65535',
    dst: ['host0', 'host1'],
    dstport: '53',
    protocol: 'udp',
    action: 'accept'
  )
  end
  data = router.create_filter_configuration_data()
  print router.convert_from_data_to_filter_string(data)
end

if __FILE__ == $0
  main()
end
