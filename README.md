# viaa-saml
Adds saml authentication to rack compatible web applications
and course grained authorization based on the SAML assertion 'apps'.

Needs Rack::Session above it in the rack middleware stack.
Depends on onelogin/ruby-saml (https://github.com/onelogin/ruby-saml.git)

If Rack::Protection is used, the layers `RemoteToken`, `SessionHijacking`
and `HttpOrigin` must be skipped to allow operation of the SAML protocol.

Example deployment via config.ru:

```ruby
require_relative 'my_awesome_app'
require_relative 'lib/viaasaml'
require 'rack/protection'

use Rack::Protection, except: [:remote_token,:session_hijacking,:http_origin]
use Rack::Session::Pool, expire_after: 1200
use ViaaSaml, configfile: '/path/to/configfile'

use Rack::Protection
run MyAwesomeApp
```
