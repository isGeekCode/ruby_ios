require 'openssl'
require 'http'
require 'jwt'
require 'securerandom'


get '/' do  
  "Please send the base 64 encoded device check token in JSON parameter key 'token' to POST /redeem"
  
end


def jwt_token
  # use the content of the .p8 key file you downloaded, it should look like this :
  #-----BEGIN PRIVATE KEY-----
  #ILIKEFOXES
  #-----END PRIVATE KEY----
  private_key = ENV['MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgXUOrlSzA/DYC3n+G
    OldH2Goyfd4KerNn1LXg96LQx4qgCgYIKoZIzj0DAQehRANCAASCRIcUQy7Jg/Vr
    T/lryBmhz42ADSCmZq4QAJpWKr/Y8Ulji8000CrSlIk4uTL5hjAKZO9tIW8Fj3n7
    KZ8617VQ']
  
  # the Key ID you saw earlier
  key_id = ENV['WL379Z2K7F']
  
  # Team ID of your Apple developer account
  team_id = ENV['ELAND RETAIL., Ltd.']

  # Elliptic curve key, used to encrypt the JWT
  ec_key = OpenSSL::PKey::EC.new(private_key)
  jwt_token = JWT.encode({iss: team_id, iat: Time.now.to_i}, ec_key, 'ES256', {kid: key_id,})
end