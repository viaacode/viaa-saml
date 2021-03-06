# viaa-saml

Adds saml authentication and course grained authorization (based on the SAML
assertions `apps` and `o`) to rack compatible web applications.

Needs `Rack::Session` above it in the rack middleware stack.
Depends on [onelogin/ruby-saml](https://github.com/onelogin/ruby-saml.git)

If Rack::Protection is used, the layers `RemoteToken`, `SessionHijacking`
and `HttpOrigin` must be skipped to allow operation of the SAML protocol.

### Example deployment via config.ru:

```ruby
require 'rack/protection'
require_relative 'lib/viaasaml'
require_relative 'my_awesome_app'

options = YAML.load_file File.expand_path('./config.yaml', File.dirname(__FILE__))

use Rack::Protection, except: [:remote_token,:session_hijacking,:http_origin]
use Rack::Session::Pool, expire_after: 1200
use ViaaSaml, options

use Rack::Protection
run MyAwesomeApp
```
