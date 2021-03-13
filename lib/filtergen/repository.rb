require 'ipaddr'
class Filtergen::Repository; end

class Filtergen::Repository
  class Rule
    attr_reader :name, :src, :dst, :srcport, :dstport, :protocol, :action

    def initialize(**kwargs)
      @name = kwargs[:name] || nil
      @src = [kwargs[:src]].flatten()
      @dst = [kwargs[:dst]].flatten()
      @srcport = [kwargs[:srcport]].flatten()
      @dstport = [kwargs[:dstport]].flatten()
      @protocol = [kwargs[:protocol]].flatten()
      @action = kwargs[:action]
    end

    def src=(value)
      @src = value
      self
    end

    def src
      @src.flatten.uniq
    end
  end
end

class Filtergen::Repository
  attr_reader :rules, :rules_object
  def initialize()
    @host_objects = []
    @port_objects = []
    @rules = []
    @rules_object = []
  end

  def add_host(**kwargs)
    @host_objects << {
      hostname: kwargs[:hostname],
      address:  kwargs[:address],
    }
    self
  end

  def add_port(**kwargs)
    @port_objects << {
      portname: kwargs[:portname],
      protocol: kwargs[:protocol],
      port:     kwargs[:port],
    }
    self
  end

  def add_rule(**kwargs)
    @rules << {
      name: kwargs[:name],
      src: [kwargs[:src]].flatten(),
      dst: [kwargs[:dst]].flatten(),
      srcport: [kwargs[:srcport]].flatten(),
      dstport: [kwargs[:dstport]].flatten(),
      protocol: [kwargs[:protocol]].flatten(),
      action: kwargs[:action],
    }
    @rules_object << Rule.new(**kwargs)
    self
  end

  def get_host(hostname)
    @host_objects.select{|e| e[:hostname] == hostname }.first
  end

  def get_port(portname)
    @port_objects.select{|e| e[:portname] == portname }.first
  end

  def resolve_host(hostnames_or_address)
    [hostnames_or_address].flatten.map{|hostname_or_address|
      begin
        IPAddr.new(hostname_or_address)
        next hostname_or_address
      rescue IPAddr::InvalidAddressError
        next get_host(hostname_or_address)[:address]
      end
      raise Exception.new("host object not found #{hostname_or_address}") if @address.nil?
    }
  end

  def resolve_port(ports_or_portranges_or_portnames, protocol: nil, type:)
    result_ports = []
    result_protocol = nil
    tmp = [ports_or_portranges_or_portnames].flatten().map{|port_or_portrange_or_portname|
      if %r"\A\d+\z|\A\d+-\d+\z" =~ port_or_portrange_or_portname
        next {prortname: nil, port: port_or_portrange_or_portname, protocol: nil}
      else
        next get_port(port_or_portrange_or_portname)
      end
    }
    result_ports = tmp.map{|e| e[:port] }
    return result_ports if type == :src

    protocols = []
    protocols << protocol
    protocols += tmp.map{|e| e[:protocol] }
    protocols.reject!(&:nil?)
    if protocols.uniq.count == 1
      result_protocol = protocols.first
    else
      raise Exception.new("protocols does not same #{protocols}")
    end
    return [result_ports, result_protocol]
  end
end

class Host
  attr_reader :address, :hostname

  def initialize(hostname_or_address, repository)
    @raw = hostname_or_address
    @address = nil
    @hostname = nil

    begin
      IPAddr.new(hostname_or_address)
      @address = hostname_or_address  # ipaddr
      @hostname = hostname_or_address # ipaddr
    rescue IPAddr::InvalidAddressError
      @address = repository.get_host(hostname_or_address)[:address] # ipaddr
      @hostname = hostname_or_address # hostname
    end

    raise Exception.new("host object not found #{hostname_or_address}") if @address.nil?
  end
end

class Port
  
end