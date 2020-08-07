require 'omniauth-oauth2'
require 'multi_json'

module OmniAuth
  module Strategies
    class Wistia < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = 'all:all'

      option :name, 'wistia'

      option :client_options, {
        :site => 'https://api.wistia.com',
        :authorize_path => '/oauth/authorize',
        :token_url => '/oauth/token',
      }

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get('https://api.wistia.com/v1/account.json').parsed
      end

      protected

      def build_access_token
        verifier = request.params["code"]
        params = {:redirect_uri => callback_url, :state => request.params["state"], :client_id => client.id, :client_secret => client.secret}
        client.auth_code.get_token(verifier, params.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
      end

    end
  end
end
