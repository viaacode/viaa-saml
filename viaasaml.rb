require  'sinatra/base'
require  'ruby-saml'

class ViaaSaml < Sinatra::Base

    CONFIGFILE = File.dirname(File.expand_path(__FILE__)) + '/config.yaml'

    use Rack::Session::Pool, expire_after: 900

    configure do
        # designed to run as middleware, protection is set in config.ru
        # if rack protection is used, the the layers RemoteToken,
        # SessionHijacking and HttpOrigin must be skipped
        # to allow the saml protocol to function
        disable :protection

        # viaa-saml settings
        saml_auth = YAML.load_file(CONFIGFILE)['saml_auth']  || {}
        exclude = Array saml_auth['exclude']
        set :app_id, saml_auth['app_id']
        set :exclude, exclude&.map { |x| Regexp.new x }

        # ruby-saml settings
        OneLogin::RubySaml::Attributes.single_value_compatibility = false
        samlsettings = OneLogin::RubySaml::Settings.new
        YAML.load_file(CONFIGFILE)['saml_metadata'].each do |k,v|
            v.each { |k,v| samlsettings.send "#{k}=", v }
        end
        samlsettings.soft = true
        samlsettings.assertion_consumer_service_binding =
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        samlsettings.assertion_consumer_logout_service_binding =
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        samlsettings.security[:authn_requests_signed]   = true
        samlsettings.security[:logout_requests_signed]  = true
        samlsettings.security[:logout_responses_signed] = true
        samlsettings.security[:metadata_signed]         = true
        samlsettings.security[:digest_method] = XMLSecurity::Document::SHA1
        samlsettings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
        set :samlsettings, samlsettings
        set :idp_url, OneLogin::RubySaml::Authrequest.new.create(samlsettings)
    end

    helpers do

        def excluded?
            settings.exclude.any? { |x| x =~ request.path_info }
        end

        def set_attributes
            session[:attributes] = Hash[@samlresponse.attributes.all]
        end

        def validate_response!
            unauthorized! 'invalid saml response' unless
                @samlresponse.is_valid?
        end

        def badrequest!(reason)
            halt 400, reason
        end

        def unauthorized!(reason)
            delete_session
            halt 401, reason
        end

        def delete_session
            session.delete(:attributes)
            session.delete(:user)
        end

        # a user is authorized for using this app when and only when
        # the app_id is listed in the :apps attribute of the saml ticket
        def saml_authorize!
            unauthorized! "no access for app_id #{settings.app_id}" unless
                @samlresponse.attributes[:apps] &&
                @samlresponse.attributes[:apps].include?(settings.app_id)
        end

        def saml_single_logout!
            logout_request = OneLogin::RubySaml::SloLogoutrequest.
                new(params[:SAMLRequest], settings: settings.samlsettings)
            badrequest! 'invalid slo request' unless logout_request.is_valid?
            delete_session
            logout_response = OneLogin::RubySaml::SloLogoutresponse.new
            redirect logout_response.
                create(settings.samlsettings, logout_request.id, nil,
                       RelayState: params[:RelayState])
        end

        def saml_authenticate!
            redirect settings.idp_url unless params[:SAMLResponse]
            @samlresponse = OneLogin::RubySaml::Response.
                new(params[:SAMLResponse], settings: settings.samlsettings)
            validate_response!
            saml_authorize!
            set_attributes
            session[:user] = @samlresponse.nameid
            redirect session.delete(:orig_url) if session[:orig_url]
        end

        def saml_logged_out!
            response = OneLogin::RubySaml::Logoutresponse.
                new(params[:SAMLResponse], settings.samlsettings)
            return unless response.validate
            delete_session
            redirect '/saml/loggedout'
        end

        def saml_logout!
            saml_single_logout! if params[:SAMLRequest]
            saml_logged_out! if params[:SAMLResponse]
            logout_request = OneLogin::RubySaml::Logoutrequest.new
            redirect logout_request.create(settings.samlsettings)
        end

    end

    get '/saml/login' do
        saml_authenticate!
    end

    post '/saml/login' do
        saml_authenticate!
    end

    post '/saml/logout' do
        saml_logout!
    end

    get '/saml/logout' do
        saml_logout!
    end

    get '/saml/loggedout' do
        "Logged out"
    end

    # Pass control to the next app in the stack
    # but authenticate first if needed
    get '/*' do
        pass if session[:user] || excluded?
        session[:orig_url] = url request.path
        saml_authenticate!
    end

end
