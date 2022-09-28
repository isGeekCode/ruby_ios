require 'openssl'
require 'http'
require 'jwt'
require 'securerandom'

def jwt_token
  # use the content of the .p8 key file you downloaded, it should look like this :
  #-----BEGIN PRIVATE KEY-----
  #ILIKEFOXES
  #-----END PRIVATE KEY----
  private_key = ENV['DEVICE_CHECK_KEY_STRING']
  
  # the Key ID you saw earlier
  key_id = ENV['DEVICE_CHECK_KEY_ID']
  
  # Team ID of your Apple developer account
  team_id = ENV['DEVICE_CHECK_TEAM_ID']

  # Elliptic curve key, used to encrypt the JWT
  ec_key = OpenSSL::PKey::EC.new(private_key)
  jwt_token = JWT.encode({iss: team_id, iat: Time.now.to_i}, ec_key, 'ES256', {kid: key_id,})
end