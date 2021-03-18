
module Filtergen
  VERSION = "0.0.1"

  # autoload :Logger, 'filtergen/logger'
  # autoload :Routers, 'filtergen/routers'
  # autoload :Repository, 'lib/filtergen/repository'
  class << self
    def logger
      @logger ||= Filtergen::Logger.new.create
    end

    def log_path=(logdev)
      logger.reopen(logdev)
    end

    def log_level=(value)
      logger.level = value1
    end

    def log_level
      %i[DEBUG INFO WARN ERROR FATAL UNKNOWN][logger.level]
    end
  end
end

require_relative './filtergen/logger'
require_relative './filtergen/routers'
require_relative './filtergen/repository'

require 'thor'
class Filtergen::Cli < Thor
  desc "parse", "do parse"
  option :juniper, type: :boolean, aliases: '-j', default: :true, desc: 'files is juniper config'
  option :vds, type: :boolean, aliases: '-v', default: :false, desc: 'files is vds config'
  def parse(*files)
    p options[:type]
    p files
  end
end