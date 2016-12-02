require  'sinatra/base'
require  'ruby-saml'

class ViaaSaml < Sinatra::Base

    CONFIGFILE = File.dirname(File.expand_path(__FILE__)) + '/config.yaml'

    use Rack::Session::Pool, expire_after: 900

    configure do
        set :protection, except: [:remote_token,:session_hijacking,:frame_options]
        saml_auth = YAML.load_file(CONFIGFILE)['saml_auth']  || {}
        set :app_id, saml_auth['app_id']
        exclude = Array saml_auth['exclude']
        set :exclude, exclude&.map { |x| Regexp.new "^#{x}" }
        OneLogin::RubySaml::Attributes.single_value_compatibility = false
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
                new(params[:SAMLRequest], settings: saml_settings)
            badrequest! 'invalid slo request' unless logout_request.is_valid?
            delete_session
            logout_response = OneLogin::RubySaml::SloLogoutresponse.new
            redirect logout_response.
                create(saml_settings, logout_request.id, nil,
                       RelayState: params[:RelayState])
        end

        def to_idp!
            auth_url = OneLogin::RubySaml::Authrequest.new.
                create(saml_settings)
            redirect(auth_url)
        end

        def saml_authenticate!
            to_idp! unless params[:SAMLResponse]
            @samlresponse = OneLogin::RubySaml::Response.
                new(params[:SAMLResponse], settings: saml_settings)
            validate_response!
            saml_authorize!
            set_attributes
            session[:user] = @samlresponse.nameid
            redirect session.delete(:orig_url) if session[:orig_url]
        end

        def saml_logged_out!
            response = OneLogin::RubySaml::Logoutresponse.
                new(params[:SAMLResponse], saml_settings)
            return unless response.validate
            delete_session
            redirect '/saml/loggedout'
        end

        def saml_logout!
            saml_single_logout! if params[:SAMLRequest]
            saml_logged_out! if params[:SAMLResponse]
            logout_request = OneLogin::RubySaml::Logoutrequest.new
            redirect logout_request.create(saml_settings)
        end

        def saml_settings
            return @settings if @settings
            settings = OneLogin::RubySaml::Settings.new
            YAML.load_file(CONFIGFILE)['saml_metadata'].each do |k,v|
                v.each { |k,v| settings.send "#{k}=", v }
            end
            settings.soft = true
            settings.assertion_consumer_service_binding =
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            settings.assertion_consumer_logout_service_binding =
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            settings.security[:authn_requests_signed]   = true
            settings.security[:logout_requests_signed]  = true
            settings.security[:logout_responses_signed] = true
            settings.security[:metadata_signed]         = true
            settings.security[:digest_method] = XMLSecurity::Document::SHA1
            settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
            @settings = settings
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
