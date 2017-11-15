require 'redmine'
require_dependency 'redmine_omniauth_isu/hooks'
require_dependency 'redmine_omniauth_isu/account_controller_patch'

Redmine::Plugin.register :redmine_omniauth_isu do
  name 'Redmine omniauth OAuth2 / ISU plugin'
  author 'Pavel Belikov'
  description 'This is a plugin for Redmine authentication with OAuth2 (ISU ITMO + CAS)'
  version '0.0.2'
  url 'https://github.com/pbelikov/redmine-omniauth-oauth-cas'
  author_url 'http://www.ifmo.ru'

  settings :default => {
    :client_id => "3",
    :client_secret => "dummy_secret",
    :url => "td5-02.tetra.nl",
    :oauth_autentification => true
  }, :partial => 'settings/isu_settings'

  Rails.configuration.to_prepare do
    AccountController.send(:include, AccountControllerPatch)
  end
end
