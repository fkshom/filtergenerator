require 'ipaddr'
class Filtergen::Repository; end

class Filtergen::Repository::Rule
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
