require 'ipaddr'
require 'forwardable'

class Filtergen::Repository; end

class Filtergen::Repository
  class Rule
    attr_reader :name, :src, :dst, :srcport, :dstport, :protocol, :action

    def initialize(**kwargs)
      @name = kwargs[:name] || nil
      @src = [kwargs[:src]].compact.flatten
      @dst = [kwargs[:dst]].compact.flatten
      @srcport = [kwargs[:srcport]].compact.flatten
      @dstport = [kwargs[:dstport]].compact.flatten
      @protocol = [kwargs[:protocol]].compact.flatten
      @action = kwargs[:action]
    end

    def src=(value)
      @src = value
      self
    end

    def src
      @src.flatten.uniq
    end

    def to_h
      return ({
        name: @name,
        src: @src,
        srcport: @srcport,
        dst: @dst,
        dstport: @dstport,
        protocol: @protocol,
        action: @action,
      })
    end
  end

  class Rules
    extend Forwardable
    include Enumerable
    def_delegators :@rules, :each

    def initialize
      @rules = []
    end

    def <<(rule)
      @rules << rule
    end

    def flatten_grep(target: :src)
      def combine_arrays(*arrays)
        if arrays.empty?
          yield
        else
          first, *rest = arrays
          first.map do |x|
            combine_arrays(*rest) {|*args| yield x, *args }
          end.flatten
            #.flatten(1)
        end
      end

      @rules.each do |rule|
        result_src = []
        rule = rule.to_h
        name = rule[:name]
        src = rule[:src]
        dst = rule[:dst]
        srcport = rule[:srcport]
        dstport, protocol = rule[:dstport], rule[:protocol]
        src = [src].flatten()
        dst = [dst].flatten()
        srcport = [srcport].flatten()
        dstport = [dstport].flatten()
        combine_arrays(src){|s|
          ret = yield ({
            name: "#{name}",
            src: s, dst: dst,
            srcport: srcport, dstport: dstport,
            protocol: protocol, action: rule[:action]
          })
          result_src << s if ret
        }
      end
      
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
    protocols.flatten!
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