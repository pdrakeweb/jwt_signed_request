# JWT Signed Request
[![travis ci build](https://api.travis-ci.org/envato/jwt_signed_request.svg)](https://travis-ci.org/envato/jwt_signed_request)

Request signing and verification for Internal APIs using JWT.

## Getting Started

Add this line to your application's Gemfile:

```ruby
gem 'jwt_signed_request'
```

then run:

```sh
$ bundle
```

## Generating EC Keys

We should be using a public key encryption alogorithm such as **ES256**. To generate your public/private key pair using **ES256** run:

```sh
$ openssl ecparam -genkey -name prime256v1 -noout -out myprivatekey.pem
$ openssl ec -in myprivatekey.pem -pubout -out mypubkey.pem
```

Store and encrypt these in your application secrets.

## Configuration

You can add signing and verification keys to the key store as your application needs them.

```ruby
private_key = <<-pem.gsub(/^\s+/, "")
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIBOQ3YIILYMV1glTKbF9oeZWzHe3SNQjAx4IbPIxNygQoAoGCCqGSM49
    AwEHoUQDQgAEuOC3ufTTnW0hVmCPNERb4LxaDE/OexDdlmXEjHYaixzYIduluGXd
    3cjg4H2gjqsY/NCpJ9nM8/AAINSrq+qPuA==
    -----END EC PRIVATE KEY-----
  pem

public_key = <<-pem.gsub(/^\s+/, "")
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuOC3ufTTnW0hVmCPNERb4LxaDE/O
  exDdlmXEjHYaixzYIduluGXd3cjg4H2gjqsY/NCpJ9nM8/AAINSrq+qPuA==
  -----END PUBLIC KEY-----
pem

require 'openssl'

JWTSignedRequest.configure_keys do |config|
  config.add_signing_key(
    key_id: 'client_a',
    key: OpenSSL::PKey::EC.new(private_key),
    algorithm: 'ES256',
  )

  config.add_verification_key(
    key_id: 'client_a',
    key: OpenSSL::PKey::EC.new(public_key),
    algorithm: 'ES256',
  )
end
```

## Signing Requests

If you have added your signing keys to the key store, you will only need to specify the `key_id` you are signing the requests with.

### Using net/http

```ruby
require 'net/http'
require 'uri'
require 'openssl'
require 'jwt_signed_request'

uri = URI('http://example.com')
req = Net::HTTP::Get.new(uri)

req['Authorization'] = JWTSignedRequest.sign(
  method: req.method,
  path: req.path,
  headers: {"Content-Type" => "application/json"},
  body: "",
  key_id: 'my-key-id',                    # used for looking up key and kid header
  lookup_key_id: 'my-alt-key-id',         # optionally override lookup key
  issuer: 'my-issuer'                     # optional
  additional_headers_to_sign: ['X-AUTH']  # optional
)

res = Net::HTTP.start(uri.hostname, uri.port) {|http|
  http.request(req)
}
```

### Using faraday

```ruby
require 'faraday'
require 'openssl'
require 'jwt_signed_request/middlewares/faraday'

conn = Faraday.new(url: URI.parse('http://example.com')) do |faraday|
  faraday.use JWTSignedRequest::Middlewares::Faraday,
    key_id: 'my-key-id',
    issuer: 'my-issuer',                    # optional
    additional_headers_to_sign: ['X-AUTH']  # optional

  faraday.adapter Faraday.default_adapter
end

conn.post do |req|
  req.url 'http://example.com'
  req.body = '{ "name": "Unagi" }'
end
```

## Verifying Requests

Please make sure you have added your verification keys to the key store. Doing so will allow the server to verify requests signed by different signing keys.


## Using Rails

```ruby
class APIController < ApplicationController
  before_action :verify_request

  ...

  private

  def verify_request
    begin
      JWTSignedRequest.verify(request: request)

    rescue JWTSignedRequest::UnauthorizedRequestError => e
      render :json => {}, :status => :unauthorized
    end
  end

end
```

### Increasing Expiry leeway

JWT tokens contain an expiry timestamp. If communication delays are large (or system clocks are sufficiently out of synch), you may need to increase the 'leeway' when verifying. For example:

```ruby
  JWTSignedRequest.verify(request: request, leeway: 55)
```

## Using Rack Middleware

```ruby
class Server < Sinatra::Base
  use JWTSignedRequest::Middlewares::Rack,
     exclude_paths: /public|health/,          # optional regex
     leeway: 100                              # optional
 end
```

## Backwards Compability

Please note that the way we sign and verify requests has changed in version 2.x.x. For documentation on how to use older versions please look [here](https://github.com/envato/jwt_signed_request/blob/master/VERSION_1.md).

We are only supporting the old API for the next couple of releases of version 2.x.x so please upgrade ASAP.

## Maintainers
- [Envato](https://github.com/envato)

## License

`JWTSignedRequest` uses MIT license. See
[`LICENSE.txt`](https://github.com/envato/jwt_signed_request/blob/master/LICENSE.txt) for
details.

## Code of conduct

We welcome contribution from everyone. Read more about it in
[`CODE_OF_CONDUCT.md`](https://github.com/envato/jwt_signed_request/blob/master/CODE_OF_CONDUCT.md)

## Contributors

Many thanks to the following contributors to this gem:

- Toan Nguyen - [@yoshdog](https://github.com/yoshdog)
- Odin Dutton - [@twe4ked](https://github.com/twe4ked)
- Sebastian von Conrad - [@vonconrad](https://github.com/vonconrad)
- Zubin Henner- [@zubin](https://github.com/zubin)
- Glenn Tweedie - [@nocache](https://github.com/nocache)
- Giancarlo Salamanca - [@salamagd](https://github.com/salamagd)
- Ben Axnick - [@bentheax](https://github.com/bentheax)
- Glen Stampoultzis - [@gstamp](https://github.com/gstamp)
- Lucas Parry - [@lparry](https://github.com/lparry)
- Chris Mckenzie - [@chrisface](https://github.com/chrisface)

## Contributing

For bug fixes, documentation changes, and small features:

1. Fork it ( https://github.com/envato/jwt_signed_request/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

For larger new features: Do everything as above, but first also make contact with the project maintainers to be sure your change fits with the project direction and you won't be wasting effort going in the wrong direction
