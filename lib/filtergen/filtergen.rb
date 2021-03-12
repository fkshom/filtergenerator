require 'ipaddr'

module Filtergen
  VERSION = "0.0.1"
end

class Filtergen::Repository; end

class Filtergen::Repository::HostObject

end

class Filtergen::Repository
  attr_reader :rules
  def initialize()
    @host_objects = []
    @port_objects = []
    @rules = []
  end

  def add_host_object(**kwargs)
    @host_objects << {
      hostname: kwargs[:hostname],
      address:  kwargs[:address],
    }
    self
  end

  def add_port_object(**kwargs)
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
      dstport: kwargs[:dstport],
      protocol: kwargs[:protocol],
      action: kwargs[:action],
    }
    self
  end

  def get_host_object(hostname)
    @host_objects.select{|e| e[:hostname] == hostname }.first
  end

  def get_port_object(portname)
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
      @address = hostname_or_address
      @hostname = nil
    rescue IPAddr::InvalidAddressError
      @address = repository.get_host_object(hostname_or_address)[:address]
      @hostname = hostname_or_address
    end

    raise Exception.new("host object not found #{hostname_or_address}") if @address.nil?
  end
end

class HostObject < Host; end

class Port
end

class Rule
end

class Filtergen::Routers; end

module RuleOperatorModule
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

  def aggregate_rules(target: [:dstport, :protocol])
    return @repository.rules.each_with_object([]) do |rule, acc|
      if ev = acc.detect{|ev| ev[:dstport] == rule[:dstport] && ev[:protocol] == rule[:protocol] }
        ev.merge!( rule.merge(
          src: [ev[:src], rule[:src]].flatten.uniq,
          dst: [ev[:dst], rule[:dst]].flatten.uniq,
          srcport: [rule[:srcport], ev[:srcport]].flatten.uniq,
          ) )
      else
        acc << rule.dup
      end
    end
  end
end

class Filtergen::Routers::Router1
  include RuleOperatorModule

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

  def create_filter_configuration_data()
    result = {}
    
    @repository.rules.each do |rule|
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

class Filtergen::Routers::Router2 < Filtergen::Routers::Router1; end
class Filtergen::Routers::Router3 < Filtergen::Routers::Router1; end

class Filtergen::Routers::VDSTF1
  include RuleOperatorModule

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

  def create_filter_configuration_data()
    result = {}
    
    @repository.rules.each do |rule|
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


  def convert_from_data_to_filter_string(data)
    result = {}
    data.each do |dcname, value1|
      result[dcname] ||= {}
      value1.each do |portgroupname, objs|
        result[dcname][portgroupname] ||= []
        objs.each do |obj|
          src = resolve_host_object(obj[:src])
          dst = resolve_host_object(obj[:dst])
          srcport = resolve_port_object(obj[:srcport], type: :src)
          dstport, protocol = resolve_port_object(obj[:dstport], protocol: obj[:protocol], type: :dst)
          src = [src].flatten()
          dst = [dst].flatten()
          srcport = [srcport].flatten()
          dstport = [dstport].flatten()

          src.product(dst, srcport, dstport){|s, d, sp, dp|
            result[dcname][portgroupname] << {
              desc: "TERM1", 
              src: s, dst: d,
              srcport: sp, dstport: dp,
              protocol: protocol, action: obj[:action]
            }
          }
          
        end
      end
    end
    return result
  end
end
