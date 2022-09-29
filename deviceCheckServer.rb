require 'sinatra'
require 'sinatra/namespace'
require 'sinatra/json'

require 'openssl'
require 'http'
require 'jwt'
require 'securerandom'

#   "Please send the base 64 encoded device check token in JSON parameter key 'token' to POST /redeem"
# end
configure do
  set :binding, '0.0.0.0'
  # set :environment, :development, :production   #직접 파일에서 구분가능함.
end

# 빌드에 따라 메세지가 다름
get '/' do
  notice = "Please send the base 64 encoded device check token in JSON parameter key 'token' to POST"
  res = 'Hello sinatra....'
  res = 'This is development' if settings.development?
  res = 'This is production' if settings.production?
  res = 'This is test' if settings.test?
  
  res
end

# 루비서버로부터 json을 리턴받기위한 API 
post '/test' do
  res = '축하축하'
  msg = res+' '+'루비서버에서 보낸 메세지'

  return json({ message: msg, redeemable: true })

end

# 앱에서 요청한 바디값을 확인하는 API
post '/requestToken' do
  begin
    request_payload = JSON.parse request.body.read
  rescue JSON::ParserError
    return json({ message: 'please supply a valid token parameter', redeemable: false })
  end

  msg = '앱에서 요청한 body value:' +' '+ request_payload['token']

  return json({ message: msg, redeemable: true })

end


post '/redeem' do
  begin
    request_payload = JSON.parse request.body.read
  rescue JSON::ParserError
    return json({ message: 'please supply a valid token parameter', redeemable: false })
  end

  # request_payload['token'] is the 'token' parameter we sent in the iOS app
  unless request_payload.key? 'token'
    return json({ message: 'please supply a token', redeemable: false })
  end

  response = query_two_bits(request_payload['token'])

  unless response.status == 200
    return json({ message: 'Error communicating with Apple server', redeemable: false })
  end

  begin
    response_hash = JSON.parse response.body
  rescue JSON::ParserError
    # if status 200 and no json returned, means the state was not set previously, we set them to nil / null
    response_hash = { bit0: nil, bit1: nil }
  end
  # if the bit0 has been set and set to true, means user has already redeemed using their phone
  if response_hash.key? 'bit0'
    if response_hash['bit0'] == true
      return json({ message: 'You have already redeemed it previously', redeemable: false })
    end
  end

  # update the first bit to true, and tell the iOS app user can redeem the free gift
  update_two_bits(request_payload['token'], true, false)

  json({ message: 'Congratulations! You have redeemed the reward', redeemable: true })
end


post '/reset' do
  begin
    request_payload = JSON.parse request.body.read
  rescue JSON::ParserError
    return json({ message: 'please supply a valid token parameter' })
  end

  # request_payload['token'] is the 'token' parameter we sent in the iOS app
  unless request_payload.key? 'token'
    return json({ message: 'please supply a token', redeemable: false })
  end

  response = query_two_bits(request_payload['token'])

  unless response.status == 200
    return json({ message: 'Error communicating with Apple server' })
  end

   # reset the first bit to false
  update_two_bits(request_payload['token'], false, false)

  json({ message: 'First bit reseted to false, you can redeem reward now' })
end

def jwt_token

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


def query_two_bits(device_token)
  payload = {
    'device_token' => device_token,
    'timestamp' => (Time.now.to_f * 1000).to_i,
    'transaction_id' => SecureRandom.uuid
  }

  response = HTTP.auth("Bearer #{jwt_token}").post(settings.query_url, json: payload)

  # if there is no bit state set before, apple will return the string 'Bit State Not Found' instead of json

  # if the bit state was set before, below will be returned
  #{"bit0":false,"bit1":false,"last_update_time":"2018-10"}
end

def update_two_bits(device_token, bit_zero, bit_one)
  payload = {
    'device_token' => device_token,
    'timestamp' => (Time.now.to_f * 1000).to_i,
    'transaction_id' => SecureRandom.uuid,
    'bit0': bit_zero,
    'bit1': bit_one
  }

  response = HTTP.auth("Bearer #{jwt_token}").post(settings.update_url, json: payload)
  # Apple will return status 200 with blank response body if the update is successful
end