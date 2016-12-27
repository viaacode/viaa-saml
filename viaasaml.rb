require 'ruby-saml'
require 'yaml'

class ViaaSaml

    def initialize(app, options={})
        @app = app
        configfile = options[:configfile] ||
            File.expand_path('../config.yaml/',__FILE__)

        # viaa-saml settings
        saml_auth = YAML.load_file(configfile)['saml_auth']  || {}
        exclude = Array saml_auth['exclude']
        @app_id = saml_auth['app_id']
        @exclude = exclude&.map { |x| Regexp.new x }

        # ruby-saml settings
        samlsettings = OneLogin::RubySaml::Settings.new
        YAML.load_file(configfile)['saml_metadata'].each do |k,v|
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
        @samlsettings = samlsettings
        @samlsettings.freeze
    end

    def excluded?
        @exclude.any? { |x| x =~ @request.path_info }
    end

    def delete_session
        session.delete(:attributes)
        session.delete(:user)
    end

    def redirect_to_idp
        idp_url = OneLogin::RubySaml::Authrequest.new.create(@samlsettings)
        session[:orig_url] = @request.url
        redirect idp_url
    end

    def redirect_to_app
        redirect session.delete(:orig_url)
    end

    def badrequest(reason)
        halt 400, reason
    end

    def unauthorized(reason)
        delete_session
        halt 401, reason
    end

    def redirect(url)
        response = Rack::Response.new
        response.redirect url
        response.finish
    end

    def halt(code,reason)
        delete_session
        response = Rack::Response.new
        response.status = code
        response.body = [reason]
        response.finish
    end

    def app_session
        return badrequest 'missing SAMLresponse' unless
        params['SAMLResponse']

        samlresponse = OneLogin::RubySaml::Response.
            new(params['SAMLResponse'], settings: @samlsettings)

        return unauthorized 'invalid SAML response' unless
        samlresponse.is_valid?

        # a user is authorized for using this app when and only when
        # the app_id is listed in the :apps attribute of the saml ticket
        return unauthorized "no access for app_id #{@app_id}" unless
        samlresponse.attributes.multi(:apps)&.include?(@app_id)

        session[:attributes] = Hash[samlresponse.attributes.all]
        session[:user] = samlresponse.nameid
        redirect_to_app
    end

    # SLO request from idP: terminate the session and send an SLO response
    def saml_slo_response
        logout_request = OneLogin::RubySaml::SloLogoutrequest.
            new(params['SAMLRequest'], settings: @samlsettings)

        return badrequest 'invalid SAML slo request' unless logout_request.is_valid?

        delete_session
        logout_response = OneLogin::RubySaml::SloLogoutresponse.new.create(
            @samlsettings, logout_request.id, nil, RelayState: params['RelayState']
        )
        redirect logout_response
    end

    # Logout response from idP: terminate the session
    def terminate_session
        response = OneLogin::RubySaml::Logoutresponse.
            new(params['SAMLResponse'], @samlsettings)
        return badrequest, 'invalid SAML response' unless response.validate
        # halts deletes the session
        halt 200, 'Logged out, session ended'
    end

    def saml_logout
        # SLO request from idP
        return saml_slo_response if params['SAMLRequest']

        # Logout response from idP
        return terminate_session if params['SAMLResponse']

        # no SAML param: logout request from the user
        settings = @samlsettings.dup
        settings.name_identifier_value = session[:user]
        logout_request = OneLogin::RubySaml::Logoutrequest.new.create(settings)
        redirect logout_request
    end

    def params
        @request.params
    end

    def session
        @request.session
    end

    def saml_logout_callback?
        @request.url == @samlsettings.assertion_consumer_logout_service_url
    end

    def saml_login_callback?
        @request.url == @samlsettings.assertion_consumer_service_url
    end

    def authenticated?
        !session[:user].nil?
    end

    def call env
        @request = Rack::Request.new env

        return app_session if saml_login_callback?
        return saml_logout if saml_logout_callback?

        return @app.call env if authenticated? || excluded?

        # authenticate the user
        redirect_to_idp
    end

end
