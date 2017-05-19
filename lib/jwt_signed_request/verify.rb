require 'jwt_signed_request/headers'

module JWTSignedRequest
  class Verify
    def self.call(*args)
      new(*args).call
    end

    # TODO: algorithm is deprecated and will be removed in future
    def initialize(request:, secret_key:, algorithm: nil, leeway: nil)
      @request = request
      @secret_key = secret_key
      @algorithm = algorithm
      @leeway = leeway
    end

    def call
      if jwt_token.nil?
        raise MissingAuthorizationHeaderError, "Missing Authorization header in the request"
      end

      unless verified_request?
        raise RequestVerificationFailedError, "Request failed verification"
      end
    end

    private

    attr_reader :request, :secret_key, :algorithm, :leeway

    def jwt_token
      @jwt_token ||= Headers.fetch('Authorization', request)
    end

    def claims
      @claims ||= begin
        verify = true
        options = {}

        if leeway
          # TODO: Once JWT v2.0.0 has been released, we should upgrade to it
          # and start using `exp_leeway` instead 'leeway' will still work, but
          # 'exp_leeway' is more explicit and is the documented way to do it.
          #
          # See https://github.com/jwt/ruby-jwt/pull/187.
          options[:leeway] = leeway.to_i
        end

        JWT.decode(jwt_token, secret_key, verify, options)[0]
      rescue ::JWT::DecodeError => e
        raise JWTDecodeError, e.message
      end
    end

    def verified_request?
      claims['method'].to_s.downcase == request.request_method.downcase &&
        claims['path'] == request.fullpath &&
        claims['body_sha'] == Digest::SHA256.hexdigest(request_body) &&
        verified_headers?
    end

    def request_body
      string = request.body.read
      request.body.rewind
      string
    end

    def verified_headers?
      parsed_headers = begin
        JSON.parse(claims['headers'].to_s)
      rescue JSON::ParserError
        {}
      end

      parsed_headers.all? do |header_key, header_value|
        Headers.fetch(header_key, request) == header_value
      end
    end
  end
end