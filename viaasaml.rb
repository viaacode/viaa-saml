require 'rack'
require 'ruby-saml'
require 'yaml'

class ViaaSaml

    class SamlRequest < Rack::Request

        # class instance variables
        class << self
            attr_accessor :samlsettings, :org_id, :app_id
        end

        def authenticate!
            return app_session if login_callback?
            return logout if logout_callback?
            # authenticate the user if neeeded
            return redirect_to_idp unless authenticated?
            # if we get here, we have an authenticated session
            Rack::Response.new 'accepted', 202
        end

        private

        def samlsettings
            self.class.samlsettings
        end

        def authenticated?
            !self.session[:user].nil?
        end

        def delete_session
            self.session.delete(:user)
            self.session.delete(:attributes)
        end

        def redirect_to_idp
            idp_url = OneLogin::RubySaml::Authrequest.new.create(samlsettings)
            self.session[:orig_url] = self.url
            redirect idp_url
        end

        def back_to_app
            redirect self.session.delete(:orig_url)
        end

        def badrequest reason
            halt 400, reason
        end

        def unauthorized reason
            delete_session
            halt 401, reason
        end

        def redirect url
            response = Rack::Response.new
            response.redirect url
            response
        end

        def halt code,reason
            delete_session
            Rack::Response.new reason, code
        end

        def app_session
            return badrequest 'missing SAMLresponse' unless
            self.params['SAMLResponse']

            samlresponse = OneLogin::RubySaml::Response.
                new(self.params['SAMLResponse'], settings: samlsettings)

            return unauthorized 'invalid SAML response' unless samlresponse.is_valid?

            # a user is authorized for using this app when and only when
            # the app_id is listed in the :apps attribute of the saml ticket
            app_id = self.class.app_id
            return unauthorized "unauthorized for this app" if app_id &&
                !samlresponse.attributes.multi(:apps)&.include?(app_id)

            # a user is authorized for using this app when and only when
            # the user is member of an organisation in org_id
            org_id = self.class.org_id
            return unauthorized "unauthorized organisation" if org_id &&
                !org_id.include?(samlresponse.attributes[:o])

            # Login successfull, setup session
            self.session[:attributes] = Hash[samlresponse.attributes.all]
            self.session[:user] = samlresponse.nameid
            back_to_app
        end

        # SLO request from idP: terminate the session and send an SLO response
        def saml_slo_response
            logout_request = OneLogin::RubySaml::SloLogoutrequest.
                new(self.params['SAMLRequest'], settings: samlsettings)

            return badrequest 'invalid SAML slo request' unless logout_request.is_valid?

            delete_session
            logout_response = OneLogin::RubySaml::SloLogoutresponse.new.create(
                samlsettings, logout_request.id, nil, RelayState: self.params['RelayState']
            )
            redirect logout_response
        end

        # Logout response from idP: terminate the session
        def terminate_session
            response = OneLogin::RubySaml::Logoutresponse.
                new(self.params['SAMLResponse'], samlsettings)
            return badrequest, 'invalid SAML response' unless response.validate
            # halts deletes the session
            halt 200, 'Logged out, session ended'
        end

        def logout
            # SLO request from idP
            return saml_slo_response if self.params['SAMLRequest']

            # Logout response from idP
            return terminate_session if self.params['SAMLResponse']

            # no SAML param: logout request from the user
            settings = samlsettings.dup
            settings.name_identifier_value = self.session[:user]
            logout_request = OneLogin::RubySaml::Logoutrequest.new.create settings
            redirect logout_request
        end

        def logout_callback?
            self.url == samlsettings.assertion_consumer_logout_service_url
        end

        def login_callback?
            self.url == samlsettings.assertion_consumer_service_url
        end

    end

    def initialize app, options
        @app = app
        SamlRequest.app_id = options['saml_app_id']
        SamlRequest.org_id = options['saml_org_id']

        samlsettings = OneLogin::RubySaml::Settings.new
        options['saml_metadata'].each do |k,v|
            samlsettings.send "#{k}=", v
        end
        samlsettings.soft = true
        samlsettings.assertion_consumer_service_binding =
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        samlsettings.assertion_consumer_logout_service_binding =
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        samlsettings.name_identifier_format =
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        samlsettings.security[:authn_requests_signed]   = true
        samlsettings.security[:logout_requests_signed]  = true
        samlsettings.security[:logout_responses_signed] = true
        samlsettings.security[:metadata_signed]         = true
        samlsettings.security[:want_assertions_signed]  = true
        samlsettings.security[:digest_method] = XMLSecurity::Document::SHA1
        samlsettings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
        SamlRequest.samlsettings = samlsettings
    end

    def call env
        unless @app.respond_to?(:public?) && @app.public?(env['PATH_INFO'])
            request = SamlRequest.new env
            samlresponse = request.authenticate!
            # Play the SAML game until we have a valid SAML session
            return samlresponse.finish unless samlresponse.accepted?
        end
        @app.call env
    end

end
