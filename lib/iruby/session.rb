# Backport of uuid

require 'securerandom'
# Backport of missing SecureRandom methods from 1.9

module SecureRandom
  class << self
    def method_missing(method_sym, *arguments, &block)
      case method_sym
      when :urlsafe_base64
        r19_urlsafe_base64(*arguments)
      when :uuid
        r19_uuid(*arguments)
      else
        super
      end
    end
    
    private
    def r19_urlsafe_base64(n=nil, padding=false)
      s = [random_bytes(n)].pack("m*")
      s.delete!("\n")
      s.tr!("+/", "-_")
      s.delete!("=") if !padding
      s
    end

    def r19_uuid
      ary = random_bytes(16).unpack("NnnnnN")
      ary[2] = (ary[2] & 0x0fff) | 0x4000
      ary[3] = (ary[3] & 0x3fff) | 0x8000
      "%08x-%04x-%04x-%04x-%04x%08x" % ary
    end
  end
end

module IRuby
  class Session
    DELIM = '<IDS|MSG>'

    def initialize(username, config)
      @username = username
      @session = SecureRandom.uuid
      @msg_id = 0
      if config['key'] && config['signature_scheme']
        raise 'Unknown signature scheme' unless config['signature_scheme'] =~ /\Ahmac-(.*)\Z/
        @hmac = OpenSSL::HMAC.new(config['key'], OpenSSL::Digest::Digest.new($1))
      end
    end

    # Build and send a message
    def send(socket, type, content, ident=nil)
      header = {
        :msg_type => type,
        :msg_id =>   @msg_id,
        :username => @username,
        :session =>  @session
      }
      @msg_id += 1

      list = serialize(header, content, ident)
      list.each_with_index do |part, i|
        socket.send_string(part, i == list.size - 1 ? 0 : ZMQ::SNDMORE)
      end
    end

    # Receive a message and decode it
    def recv(socket, mode)
      msg = []
      while msg.empty? || socket.more_parts?
        begin
          frame = ''
          rc = socket.recv_string(frame, mode)
          ZMQ::Util.error_check('zmq_msg_send', rc)
          msg << frame
        rescue
        end
      end

      i = msg.index(DELIM)
      idents, msg_list = msg[0..i-1], msg[i+1..-1]
      msg = unserialize(msg_list)
      @last_received_header = msg[:header]
      return idents, msg
    end

    private

    def serialize(header, content, ident)
      msg = [MultiJson.dump(header),
             MultiJson.dump(@last_received_header || {}),
             '{}',
             MultiJson.dump(content || {})]
      ([ident].flatten.compact << DELIM << sign(msg)) + msg
    end

    def unserialize(msg_list)
      minlen = 5
      raise 'malformed message, must have at least #{minlen} elements' unless msg_list.length >= minlen
      s, header, parent_header, metadata, content, buffers = *msg_list
      raise 'Invalid signature' unless s == sign(msg_list[1..-1])
      {
        :header => MultiJson.load(header),
        :parent_header => MultiJson.load(parent_header),
        :metadata => MultiJson.load(metadata),
        :content => MultiJson.load(content),
        :buffers => buffers
      }
    end

    # Sign using HMAC
    def sign(list)
      if @hmac
        @hmac.reset
        list.each {|m| @hmac.update(m) }
        @hmac.hexdigest
      else
        ''
      end
    end
  end
end
