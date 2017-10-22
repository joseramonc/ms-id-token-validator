require 'net/http'
require 'json/jwt'

module MsIdToken
  class BadIdTokenFormat < StandardError; end
  class BadIdTokenHeaderFormat < StandardError; end
  class BadIdTokenPayloadFormat < StandardError; end
  class UnableToFetchMsConfig < StandardError; end
  class UnableToFetchMsCerts < StandardError; end
  class BadPublicKeysFormat < StandardError; end
  class UnableToFindMsCertsUri < StandardError; end
  class InvalidAudience < StandardError; end
  class IdTokenExpired < StandardError; end
  class IdTokenNotYetValid < StandardError; end

  class Validator
    MS_CONFIG_URI = 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration'.freeze
    CACHED_CERTS_EXPIRY = 3600
    TOKEN_TYPE = 'JWT'.freeze
    TOKEN_ALGORITHM = 'RS256'.freeze
    TOKEN_PUBLIC_KEY_SIGN = [:kid, :x5t].freeze

    def initialize(options={})
      @cached_certs_expiry = options.fetch(:expiry, CACHED_CERTS_EXPIRY)
    end

    def check(id_token, audience)
      encoded_header, encoded_payload, signature = id_token.split('.')

      raise BadIdTokenFormat if encoded_payload.nil? || signature.nil?

      header = JSON.parse(Base64.decode64(encoded_header), symbolize_names: true)

      public_key_sign = get_public_key_sign(header)

      public_key = get_cert(public_key_sign)

      payload = JSON::JWT.decode(id_token, public_key).symbolize_keys

      verify_payload(payload, audience)

      payload
    end

    def verify_header(header)
      valid_header = header[:typ] == TOKEN_TYPE && header[:alg] == TOKEN_ALGORITHM

      valid_header &= !(header[:kid].nil? && header[:x5t].nil?)

      raise BadIdTokenHeaderFormat unless valid_header
    end

    def verify_payload(payload, audience)
      raise BadIdTokenPayloadFormat if payload[:aud].nil? || payload[:exp].nil? || payload[:nbf].nil?

      raise InvalidAudience if payload[:aud] != audience

      current_time = Time.current.to_i

      raise IdTokenExpired if payload[:exp] < current_time

      raise IdTokenNotYetValid if payload[:nbf] > current_time
    end

    def get_public_key_sign(header)
      verify_header(header)

      header.select { |key, _| TOKEN_PUBLIC_KEY_SIGN.include?(key) }
    end

    def get_cert(public_key_sign)
      public_key_sign_type, public_key_sign_value = public_key_sign.to_a.first

      public_key = ms_public_keys.find do |public_key|
        public_key[public_key_sign_type.to_sym] == public_key_sign_value
      end

      JSON::JWK::Set.new(public_key)
    end

    def ms_public_keys
      if @ms_public_keys.nil? || cached_certs_expired?
        @ms_public_keys = fetch_public_keys
        @last_cached_at = Time.current.to_i
      end

      @ms_public_keys
    end

    def fetch_public_keys
      ms_certs_uri = fetch_ms_config[:jwks_uri]

      raise UnableToFindMsCertsUri if ms_certs_uri.nil?

      uri = URI(ms_certs_uri)
      response = Net::HTTP.get_response(uri)

      raise UnableToFetchMsConfig unless response.is_a?(Net::HTTPSuccess)

      keys = JSON.parse(response.body, symbolize_names: true)[:keys]

      raise BadPublicKeysFormat if keys.nil? || !keys.is_a?(Array)

      keys
    end

    def fetch_ms_config
      uri = URI(MS_CONFIG_URI)
      response = Net::HTTP.get_response(uri)

      raise UnableToFetchMsConfig unless response.is_a?(Net::HTTPSuccess)

      JSON.parse(response.body, symbolize_names: true)
    end

    def cached_certs_expired?
      !(@last_cached_at.is_a?(Integer) && @last_cached_at + @cached_certs_expiry >= Time.current.to_i)
    end
  end
end
