require "omniauth-oauth2"
require "multi_json"

module OmniAuth
  module Strategies
    class Wistia < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = "all:all"

      option :name, "wistia"

      option :client_options, {
        site: "https://api.wistia.com",
        authorize_path: "/oauth/authorize",
        token_url: "/oauth/token"
      }

      uid do
        raw_info["id"]
      end

      info do
        {
          name: raw_info["name"]
        }
      end

      extra do
        {
          "raw_info" => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get("https://api.wistia.com/v1/account.json").parsed
      end

      protected

      # Override callback URL to strip query params, Wistia is strict about this (as per oauth2 spec).
      def callback_url
        full_host + script_name + callback_path
      end
    end
  end
end
