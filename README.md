# viaa-saml
Rack middleware that adds saml authentication to the apps further in the rack pipeline

Typically deployed via config.ru, for example:

```ruby
require_relative 'my_awesome_app'
require_relative 'lib/viaasaml'

use ViaaSaml
run MyAwesomeApp
```
