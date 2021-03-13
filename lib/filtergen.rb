require 'ipaddr'

module Filtergen
  VERSION = "0.0.1"
end

require_relative 'filtergen/repository'


class Filtergen::Routers; end

module RuleOperatorModule
  def resolve_host_object(hostnames)
    [hostnames].flatten().map{|hostname_or_address|
      begin
        IPAddr.new(hostname_or_address)
        next hostname_or_address
      rescue IPAddr::InvalidAddressError
        next @repository.get_host(hostname_or_address)[:address]
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
        next @repository.get_port(port_or_portrange_or_portname)
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

  def aggregate_rules(by: [:dstport, :protocol])
    return @repository.rules.each_with_object([]) do |rule, acc|
      if ev = acc.detect{|ev| by.all?{|t| ev[t] == rule[t] } }
        ev.merge!( rule.merge(
          src: [ev[:src], rule[:src]].flatten.uniq,
          dst: [ev[:dst], rule[:dst]].flatten.uniq,
          srcport: [rule[:srcport], ev[:srcport]].flatten.uniq,
          dstport: [rule[:dstport], ev[:dstport]].flatten.uniq,
          protocol: [rule[:protocol], ev[:protocol]].flatten.uniq,
          action: rule[:action],
          ) )
      else
        acc << rule.dup
      end
    end
  end

  def flatten_rules(order: [:src, :dst, :srcport, :dstport, :protocol, :action])
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

    @repository.rules.each do |p_rule|
      @interfaces.each do |interface|
        rule = Marshal.load(Marshal.dump(p_rule))
        rule[:src] = rule[:src].select{|s| 
          ho = Host.new(s, @repository)
          IPAddr.new(interface[:address]).include?(IPAddr.new(ho.address))
        }
        filtername = interface[:filtername]
        result[ filtername ] ||= {}
        result[ filtername ][ rule[:name] ] = {
          src: [rule[:src]].flatten(),
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

    @repository.rules.each do |p_rule|
      @portgroups.each do |portgroup|
        rule = Marshal.load(Marshal.dump(p_rule))
        rule[:src] = rule[:src].select{|s| 
          ho = Host.new(s, @repository)
          IPAddr.new(portgroup[:address]).include?(IPAddr.new(ho.address))
        }
        dcname = portgroup[:dcname]
        pgname = portgroup[:portgroupname]
        result[ dcname ] ||= {}
        result[ dcname ][ pgname ] ||= []
        result[ dcname ][ pgname ] << {
          desc: rule[:name],
          src: [rule[:src]].flatten(),
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
