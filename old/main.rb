require 'yaml'
require_relative "lib/filtergen"
require 'optparse'

def parse_options(argv = ARGV)
  op = OptionParser.new

  self.class.module_eval do
    define_method(:usage) do |msg = nil|
      puts op.to_s
      puts "error: #{msg}" if msg
      exit 1
    end
  end

  # default value
  opts = {
    boolean: false,
    string: '',
    integer: 0,
    array: [],
  }

  # boolean
  op.on('-b', '--[no-]boolean', "boolean value (default: #{opts[:boolean]})") {|v|
    opts[:boolean] = v
  }
  # string argument
  op.on('-s', '--string VALUE', "string value (default: #{opts[:string]})") {|v|
    opts[:string] = v
  }
  # array argument
  op.on('-a', '--array one,two,three', Array, "array value (default: #{opts[:array]})") {|v|
    opts[:array] = v
  }
  # optional integer argument (just cast)
  op.on('-i', '--integer [VALUE]', "integer value (default: #{opts[:integer]})") {|v|
    opts[:integer] = v.to_i
  }

  op.banner += ' ARG1 ARG2'
  # op.parse! は破壊的だが、op.parse は破壊的ではない (ARGV を改変しない)
  begin
    args = op.parse(argv)
  rescue OptionParser::InvalidOption => e
    usage e.message
  end

  if args.size < 2
    usage 'number of arguments is less than 2'
  end

  [opts, args]
end

def main()
  #opts, argv = parse_options

  l_definitions = YAML.load_file("sample_data/definitions.yml")

  repository = Filtergen::Repository.new()
  (l_definitions['hostObject'] || []).each do |host_object|
    repository.add_host(hostname: host_object['hostname'], address: host_object['address'])
  end
  (l_definitions['portObject'] || []).each do |port_object|
    repository.add_port(portname: port_object['portname'], protocol: port_object['protocol'], port: port_object['port'])
  end
  (l_definitions['rule'] || []).each do |rule|
    repository.add_rule(
      name: rule['name'],
      src: rule['src'],
      srcport: rule['srcport'],
      dst: rule['dst'],
      dstport: rule['dstport'],
      protocol: rule['protocol'],
      action: rule['action'],
    )
  end
  
  l_interfaces = YAML.load_file("sample_data/interfaces.yml")
  router = Filtergen::Routers::Router1.new()
  router.set_repository(repository)

  (l_interfaces['router1'] || []).each do |interface|
    router.assign_interface(interfacename: interface['interfacename'], filtername: interface['filtername'],
      direction: interface['direction'], address: interface['address'])
  end

  rules = router.create_router_rules()
  pp rules.class
  pp rules.to_h
  pp rules.to_s

  router = Filtergen::Routers::VDSTF1.new()
  router.set_repository(repository)

  (l_interfaces['vdstf1'] || []).each do |interface|
    router.assign_portgroup(dcname: interface['dcname'], portgroupname: interface['pgname'],
      address: interface['address'])
  end

  rules = router.create_router_rules()
  pp rules.class
  pp rules.to_h
  pp rules.to_s
  pp rules.to_yaml
end

if __FILE__ == $0
  main()
end
