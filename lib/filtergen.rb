

module Filtergen
  VERSION = "0.0.1"

  autoload :Logger, 'filtergen/logger'
  autoload :Routers, 'filtergen/routers'
  autoload :Repository, 'filtergen/repository'
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
