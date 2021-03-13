require 'yaml'
require_relative "lib/filtergen"

def main()
  l_interfaces = YAML.load_file("interfaces.yml")
  l_definitions = YAML.load_file("definitions.yml")

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
  end
  (l_definitions['rule'] || []).each do |rule|
    router.add_rule(
      name: rule['name'],
      src: rule['src'],
      srcport: rule['srcport'],
      dst: rule['dst'],
      dstport: rule['dstport'],
      protocol: rule['protocol'],
      action: rule['action'],
    )
    end
  data = router.create_filter_configuration_data()
  puts router.convert_from_data_to_filter_string(data).join("\n")
end

if __FILE__ == $0
  main()
end
