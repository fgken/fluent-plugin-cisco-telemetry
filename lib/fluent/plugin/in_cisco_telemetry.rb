require 'cool.io'
require 'zlib'

require 'fluent/input'

module Fluent
  class CiscoTelemetryInput < Input
    Plugin.register_input('cisco_telemetry', self)

    config_param :port, :integer, default: 5555
    config_param :bind, :string, default: '0.0.0.0'
    config_param :tag, :string
    config_param :protocol_type, default: :tcp do |val|
      case val.downcase
      when 'tcp'
        :tcp
      else
        raise ConfigError, "cisco telemetry input protocol type should be 'tcp'"
      end
    end

    def configure(conf)
      super

      #@parser = TextParser::NetflowParser.new
      #@parser.configure(conf)
    end

    def start
      @loop = Coolio::Loop.new
      @handler = listen(method(:receive_data))
      @loop.attach(@handler)

      @thread = Thread.new(&method(:run))
    end

    def shutdown
      @loop.watchers.each { |w| w.detach }
      @loop.stop
      @handler.close
      @thread.join
    end

    def run
      @loop.run
    rescue => e
      log.error "unexpected error", error_class: e.class, error: e.message
      log.error_backtrace
    end

    protected

    def receive_data(data, host)
      record = {}
      record['host'] = "#{host}" 
      record['msg'] = data
      router.emit(@tag, Fluent::Engine.now, record)
    rescue => e
      log.warn "unexpected error on parsing", data: data.dump, error_class: e.class, error: e.message
      log.warn_backtrace
    end

    private

    def listen(callback)
      log.info "listening cisco telemetry socket on #{@bind}:#{@port} with #{@protocol_type}"
      if @protocol_type == :udp
        @usock = SocketUtil.create_udp_socket(@bind)
        @usock.bind(@bind, @port)
        SocketUtil::UdpHandler.new(@usock, log, 2048, callback)
      else
        Coolio::TCPServer.new(@bind, @port, TcpHandler, log, "", callback)
      end
    end

    class TcpHandler < Coolio::Socket
      PEERADDR_FAILED = ["?", "?", "name resolusion failed", "?"]

      def initialize(io, log, delimiter, callback)
        super(io)
        if io.is_a?(TCPSocket)
          @addr = (io.peeraddr rescue PEERADDR_FAILED)

          opt = [1, @timeout.to_i].pack('I!I!')  # { int l_onoff; int l_linger; }
          io.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, opt)
        end
        @delimiter = delimiter
        @callback = callback
        @log = log
        @log.trace { "accepted fluent socket object_id=#{self.object_id}" }
        @buffer = "".force_encoding('ASCII-8BIT')
      end

      def on_connect
      end

      def on_read(data)
        @buffer << data
        pos = 0

        if 4 <= @buffer.length
          pos += 4
          msg_type = @buffer[0...pos].unpack("N")[0]
          if 4 < msg_type
            msg_len = msg_type
            if msg_len < @buffer.length
              # Type: Reset Compressor
              tlv_type = data[pos...pos+4].unpack("N")[0]
              pos += 4
              tlv_len = data[pos...pos+4].unpack("N")[0]
              pos += 4
              z = Zlib::Inflate.new()

              # Type: JSON Message
              tlv_type = data[pos...pos+4].unpack("N")[0]
              pos += 4
              tlv_len = data[pos...pos+4].unpack("N")[0]
              pos += 4
              msg_json = z.inflate(data[pos..-1])
              @callback.call(msg_json, @addr)
              @buffer = "".force_encoding('ASCII-8BIT')
            end
          else
            @buffer = "".force_encoding('ASCII-8BIT')
          end
        end
      rescue => e
        @log.error "unexpected error", error: e, error_class: e.class
        close
      end

      def on_close
        @log.trace { "closed fluent socket object_id=#{self.object_id}" }
      end
    end
  end
end
