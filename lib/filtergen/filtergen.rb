require 'ipaddr'

module Filtergen
  VERSION = "0.0.1"
end

class Filtergen::Repository; end

class Filtergen::Repository::HostObject

end

class Filtergen::Repository
  def initialize()
    @host_objects = []
    @port_objects = []
    @rules = []
  end

  def add_host_object(**kwargs)
    @host_objects << {
      hostname: kwargs[:hostname],
      address: kwargs[:address],
    }
  end

  def add_port_object(**kwargs)
    @port_objects << {
      portname: kwargs[:portname],
      protocol: kwargs[:protocol],
      port: kwargs[:port],
    }
  end

  def add_rule(**kwargs)
    @rules << {
      name: kwargs[:name],
      src: kwargs[:src], srcport: kwargs[:srcport],
      dst: kwargs[:dst], dstport: kwargs[:dstport],
      protocol: kwargs[:protocol]
    }
  end

  def get_host_object(hostname)
    @host_objects.select{|e| e[:hostname] == hostname }.first
  end

  def get_port_object(portname)
    @port_objects.select{|e| e[:portname] == portname }.first
  end
end

class HostObject
  attr_reader :address, :hostname

  def initialize(hostname_or_address, repository)
    @raw = hostname_or_address
    @address = nil
    @hostname = nil

    begin
      IPAddr.new(hostname_or_address)
      @address = hostname_or_address
      @hostname = nil
    rescue IPAddr::InvalidAddressError
      @address = repository.get_host_object(hostname_or_address)[:address]
      @hostname = hostname_or_address
    end

    raise Exception.new("host object not found #{hostname_or_address}") if @address.nil?
  end
end

class Filtergen::Routers; end

class Filtergen::Routers::Router1
  def initialize()
    @interfaces = []
    @rules = []
    @repository = nil
  end

  def assign_interface(interfacename:, filtername:, direction:, address:)
    @interfaces << {
      interfacename: interfacename,
      filtername: filtername,
      address: address,
    }
  end

  def set_repository(func)
    @repository = func
  end

  def add_rule(**rule)
    @rules << {
      name: rule[:name],
      src: [rule[:src]].flatten(),
      dst: [rule[:dst]].flatten(),
      srcport: [rule[:srcport]].flatten(),
      dstport: rule[:dstport],
      protocol: rule[:protocol],
      action: rule[:action],
    }
  end

  def create_filter_configuration_data()
    result = {}
    
    @rules.each do |rule|
      src_grouped = rule[:src].group_by{|e|
        #eが所属しているインタフェースのフィルタ名をキーとし、所属するIPアドレスの配列をValueで返す
        ho = HostObject.new(e, @repository)
        @interfaces.select{|interface| 
          raise Exception.new("address not found #{ho}") if ho.address.nil?
          IPAddr.new(interface[:address]).include?(
            IPAddr.new(ho.address))}.first[:filtername]
      }
      src_grouped.each do |filtername, srcs|
        result[ filtername ] ||= {}
        name = rule[:name]
        result[ filtername ][name] = {
          src: [srcs].flatten(),
          dst: [rule[:dst]].flatten(),
          srcport: [rule[:srcport]].flatten(),
          dstport: rule[:dstport],
          protocol: rule[:protocol],
          action: rule[:action],
        }
      end
    end
    return result
  end

  def resolve_host_object(hostnames)
    [hostnames].flatten().map{|hostname_or_address|
      begin
        IPAddr.new(hostname_or_address)
        next hostname_or_address
      rescue IPAddr::InvalidAddressError
        next @repository.get_host_object(hostname_or_address)[:address]
      end
      raise Exception.new("host object not found #{hostname_or_address}") if @address.nil?
    }
  end

  def resolve_port_object(portnames, protocol: nil, type:)
    result_ports = []
    result_protocol = nil
    tmp = [portnames].flatten().map{|port_or_portrange_or_portname|
      if %r"\A\d+\z|\A\d+-\d+\z" =~ port_or_portrange_or_portname
        next {prortname: nil, port: port_or_portrange_or_portname, protocol: nil}
      else
        next @repository.get_port_object(port_or_portrange_or_portname)
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

  def convert_from_data_to_filter_string(data)
    result = []
    data.each do |filtername, value1|
      value1.each do |termname, obj|
        src = resolve_host_object(obj[:src])
        [src].flatten().each do |e|
          result << "set firewall filter #{filtername} term #{termname} source-address #{e}"
        end

        dst = resolve_host_object(obj[:dst])
        [dst].flatten().each do |e|
          result << "set firewall filter #{filtername} term #{termname} destination-address #{e}"
        end

        srcport = resolve_port_object(obj[:srcport], type: :src)
        [srcport].flatten().each do |e|
          result << "set firewall filter #{filtername} term #{termname} source-port #{e}"
        end

        dstport, protocol = resolve_port_object(obj[:dstport], protocol: obj[:protocol], type: :dst)
        [dstport].flatten().each do |e|
          result << "set firewall filter #{filtername} term #{termname} destination-port #{e}"
        end
        result << "set firewall filter #{filtername} term #{termname} protocol #{protocol}"
        action = obj[:action]
        result << "set firewall filter #{filtername} term #{termname} #{action}"
      end
    end
    return result
  end
end

class Filtergen::Routers::VDSTF1
  def initialize()
    @portgroups = []
    @rules = []
    @repository = nil
  end

  def assign_portgroup(dcname:, portgroupname:, address:)
    @portgroups << {
      dcname: dcname,
      portgroupname: portgroupname,
      address: address
    }
  end

  def set_repository(func)
    @repository = func
  end

  def add_rule(**rule)
    @rules << {
      name: rule[:name],
      src: [rule[:src]].flatten(),
      dst: [rule[:dst]].flatten(),
      srcport: [rule[:srcport]].flatten(),
      dstport: rule[:dstport],
      protocol: rule[:protocol],
      action: rule[:action],
    }
  end

  def create_filter_configuration_data()
    result = {}
    
    @rules.each do |rule|
      src_grouped = rule[:src].group_by{|e|
        #eが所属しているインタフェースのフィルタ名をキーとし、所属するIPアドレスの配列をValueで返す
        ho = HostObject.new(e, @repository)
        @portgroups.select{|portgroup| 
          raise Exception.new("address not found #{ho}") if ho.address.nil?
          IPAddr.new(portgroup[:address]).include?(
            IPAddr.new(ho.address))
        }.first.values_at(:dcname, :portgroupname)
      }
      src_grouped.each do |dcname_portgroupname, srcs|
        dcname, portgroupname = *dcname_portgroupname
        result[ dcname ] ||= {}
        result[ dcname ][ portgroupname ] ||= []
        name = rule[:name]
        result[ dcname ][ portgroupname ] << {
          desc: name,
          src: [srcs].flatten(),
          dst: [rule[:dst]].flatten(),
          srcport: [rule[:srcport]].flatten(),
          dstport: rule[:dstport],
          protocol: rule[:protocol],
          action: rule[:action],
        }
      end
    end
    return result
  end

  def resolve_host_object(hostnames)
    [hostnames].flatten().map{|hostname_or_address|
      begin
        IPAddr.new(hostname_or_address)
        next hostname_or_address
      rescue IPAddr::InvalidAddressError
        next @repository.get_host_object(hostname_or_address)[:address]
      end
      raise Exception.new("host object not found #{hostname_or_address}") if @address.nil?
    }
  end

  def resolve_port_object(portnames, protocol: nil, type:)
    result_ports = []
    result_protocol = nil
    tmp = [portnames].flatten().map{|port_or_portrange_or_portname|
      if %r"\A\d+\z|\A\d+-\d+\z" =~ port_or_portrange_or_portname
        next {prortname: nil, port: port_or_portrange_or_portname, protocol: nil}
      else
        next @repository.get_port_object(port_or_portrange_or_portname)
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

  def convert_from_data_to_filter_string(data)
    result = []
    data.each do |dcname, value1|
      value1.each do |portgroupname, objs|
        objs.each do |obj|
          src = resolve_host_object(obj[:src])
          [src].flatten().each do |e|
            result << "set firewall filter #{dcname} term #{portgroupname} source-address #{e}"
          end

          dst = resolve_host_object(obj[:dst])
          [dst].flatten().each do |e|
            result << "set firewall filter #{dcname} term #{portgroupname} destination-address #{e}"
          end

          srcport = resolve_port_object(obj[:srcport], type: :src)
          [srcport].flatten().each do |e|
            result << "set firewall filter #{dcname} term #{portgroupname} source-port #{e}"
          end

          dstport, protocol = resolve_port_object(obj[:dstport], protocol: obj[:protocol], type: :dst)
          [dstport].flatten().each do |e|
            result << "set firewall filter #{dcname} term #{portgroupname} destination-port #{e}"
          end
          result << "set firewall filter #{dcname} term #{portgroupname} protocol #{protocol}"
          action = obj[:action]
          result << "set firewall filter #{dcname} term #{portgroupname} #{action}"
        end
      end
    end
    return result
  end
end