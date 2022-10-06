

unless ENV['RACK_ENV'] == 'production'
  require 'dotenv'
  Dotenv.load
end

require 'openssl'
require 'http'
require 'jwt'
require 'securerandom'

require 'sinatra'
require 'sinatra/namespace'
require 'sinatra/json'


configure do
  # set :'0.0.0.0'
  set :binding, '0.0.0.0'
  # set :environment, :development, :production   #직접 파일에서 구분가능함.
  set :device_check_api_url, 'https://api.devicecheck.apple.com'
  set :query_url, settings.device_check_api_url + '/v1/query_two_bits'
  set :update_url, settings.device_check_api_url + '/v1/update_two_bits'
end

# 빌드에 따라 메세지가 다름
post '/' do
  notice = "Please send the base 64 encoded device check token in JSON parameter key 'token' to POST"
  # res = 'Hello world....'
  res = 'This is dev_Server' if settings.development?
  res = 'This is prd_Server' if settings.production?
  res = 'This is test_Server' if settings.test?

  msg = res+' '+'루비서버에서 보낸 메세지'

  return json({ message: msg, redeemable: true })
end

# 루비서버로부터 json을 리턴받기위한 API 
post '/test' do
  res = '축하축하'
  msg = res+' '+'루비서버에서 보낸 메세지'

  return json({ message: msg, redeemable: true })

end

# 앱에서 요청한 바디값을 확인하는 테스트용 API
post '/requestToken' do
  begin
    # 앱에서 요청한 request의 body를 JSON으로 파싱
    request_payload = JSON.parse request.body.read
  # 예외처리: JSON파싱에러, 에러메세지 리턴
  rescue JSON::ParserError
    return json({ message: 'please supply a valid token parameter', redeemable: false })
  end

  # request_payload['token']은 iOS 앱에서 보낸 'token'
  # 파싱성공한  JSON에 'token' 이라는 Key값이 없다면 에러메세지 리턴
  unless request_payload.key? 'token'
    return json({ message: 'please supply a token', redeemable: false })
  end

  msg = '앱에서 요청한 body value:' +' '+ request_payload['token']
  return json({ message: msg, redeemable: true })

end

# 앱에서 요청한 바디값을 확인하는 테스트용 API
post '/appleServerTest' do
  # 앱에서 생성한 DCDeviceToken을 받는 부분
  begin
    request_payload = JSON.parse request.body.read
  # 예외처리: JSON파싱에러, 에러메세지 리턴
  rescue JSON::ParserError
    return json({ message: 'please supply a valid token parameter', redeemable: false })
  end

  # request_payload['token']은 iOS 앱에서 보낸 'token'
  # 파싱성공한  JSON에 'token' 이라는 Key값이 없다면 에러메세지 리턴
  unless request_payload.key? 'token'
    return json({ message: 'please supply a token', redeemable: false })
  end

  # 여기까진 
  # if response.status = 200
  #   return json({ message: '서버통신 성공', redeemable: false })
  # end
  # return json({ message: 'good', redeemable: false })
  # if response.status = 500
  #   return json({ message: 'An error occurred on the server', redeemable: false })
  # end

  # 애플서버에 해당기기의 2비트 쿼리 등록 상태 체크
  response = query_two_bits(request_payload['token'])

  # 성공메세지 200이 아닌경우, 애플서버와의 통신 에러 메세지 리턴 
  unless response.status == 200
    return json({ message: 'Error communicating with Apple server', redeemable: false })
  end

  # if response.status = 500
  #   return json({ message: 'An error occurred on the server', redeemable: false })
  # end

  #response의 body -> Dictionday JSON 형태로 JSON파싱 
  begin response_hash = JSON.parse response.body
  rescue JSON::ParserError
    # if status 200 and no json returned, means the state was not set previously, we set them to nil / null
    # 만약 status가 200이고 리턴된 json이 없다면, 이전 설정이 없어 nil로 세팅
    response_hash = { bit0: nil, bit1: nil }
  end
  # bit0이 세팅되어있고 true인 상태: 사용자가 이미 디바이스를 사용해 교환한 이력이 있음을 의미
  if response_hash.key? 'bit0'
    if response_hash['bit0'] == true
      return json({ message: 'You have already redeemed it previously', redeemable: false })
    end
  end

  json({ message: 'Congratulations! You recive Apple\'s response', redeemable: true })
end


# 서버의 bit 정보 update
post '/redeem' do
  # 앱에서 생성한 DCDeviceToken을 받는 부분
  begin
    request_payload = JSON.parse request.body.read
  # 예외처리: JSON파싱에러, 에러메세지 리턴
  rescue JSON::ParserError
    return json({ message: 'please supply a valid token parameter', redeemable: false })
  end

  # request_payload['token']은 iOS 앱에서 보낸 'token'
  # 파싱성공한  JSON에 'token' 이라는 Key값이 없다면 에러메세지 리턴
  unless request_payload.key? 'token'
    return json({ message: 'please supply a token', redeemable: false })
  end

  # 애플서버에 해당기기의 2비트 쿼리 등록 상태 체크
  response = query_two_bits(request_payload['token'])

  # 성공메세지 200이 아닌경우, 애플서버와의 통신 에러 메세지 리턴 
  unless response.status == 200
    return json({ message: 'Error communicating with Apple server', redeemable: false })
  end

  #response의 body -> Dictionday JSON 형태로 JSON파싱 
  begin response_hash = JSON.parse response.body
  rescue JSON::ParserError
    # if status 200 and no json returned, means the state was not set previously, we set them to nil / null
    # 만약 status가 200이고 리턴된 json이 없다면, 이전 설정이 없어 nil로 세팅
    response_hash = { bit0: nil, bit1: nil }
  end
  # bit0이 세팅되어있고 true인 상태: 사용자가 이미 디바이스를 사용해 교환한 이력이 있음을 의미
  if response_hash.key? 'bit0'
    if response_hash['bit0'] == true
      return json({ message: 'You have already redeemed it previously', redeemable: false })
    end
  end

  # 애플서버의 bit0을 true로 업데이트, 사용자에게 사용가능하다는 메세지 리턴
  update_two_bits(request_payload['token'], true, false)

  json({ message: 'Congratulations! You have redeemed the reward', redeemable: true })
end

# 서버의 bit 정보 초기화 ->  bit0: false, bit1: false
post '/reset' do

  # 앱에서 생성한 DCDeviceToken을 받는 부분
  begin
    request_payload = JSON.parse request.body.read
  # 예외처리: JSON파싱에러, 에러메세지 리턴
  rescue JSON::ParserError
    return json({ message: 'please supply a valid token parameter' })
  end

  # request_payload['token']은 iOS 앱에서 보낸 'token'
  # 파싱성공한  JSON에 'token' 이라는 Key값이 없다면 에러메세지 리턴
  unless request_payload.key? 'token'
    return json({ message: 'please supply a token', redeemable: false })
  end

  # 애플서버에 해당기기의 2비트 쿼리 등록 상태 체크
  response = query_two_bits(request_payload['token'])

  # 성공메세지 200이 아닌경우, 애플서버와의 통신 에러 메세지 리턴 
  unless response.status == 200
    return json({ message: 'Error communicating with Apple server' })
  end

  # 애플서버의 bit0을 false로 업데이트, 사용자에게 bit0을 false로 초기화했으며, 이제 등록가능하다는 메세지 리턴
  update_two_bits(request_payload['token'], false, false)
  json({ message: 'First bit reseted to false, you can redeem reward now' })
end

# Authorization Token (JWT Token)
# 서버가 자신의 소유인지 확인하기 위해 사용
# JWT = Header + Payload
# - Header: { "alg": "ES256", "kid": "ZG9X84CK5L" }
# - Payload: { "iss": "HZB81NQ8N6", "iat": 1516239022 }
# Encrypted with key (the .p8 key file) -> JSON Web Token

def jwt_token
  # Developer.apple에서 생성한 DeviceCheck 키 파일(.p8)안에 있는 PrivateKey
  private_key = ENV['DEVICE_CHECK_KEY_STRING']
  
  # Developer.apple에서 생성한 DeviceCheck Key ID
  key_id = ENV['DEVICE_CHECK_KEY_ID']
  
  # Developer.apple의 앱 account Team ID
  team_id = ENV['DEVICE_CHECK_TEAM_ID']

  # ECC방식으로 JWT를 암호화
  # Elliptic curve key 생성
  ec_key = OpenSSL::PKey::EC.new(private_key)
  
  jwt_token = JWT.encode({iss: team_id, iat: Time.now.to_i}, ec_key, 'ES256', {kid: key_id,})
end

=begin
장치의 2beat 쿼리 ( 상태 ) 가져오기 : Validation Check
- parameter
  - device_token: 앱에서 생성한 DCDeviceToken
- JSON Payload
  - device_token: param에 들어온 device_token
  - timstamp: Apple에 요청을 보낼 때 Unix Timestamp의 현재 시간( 밀리초 ) 입니다.
  - transaction_id: SecureRandom모듈을 이용해 랜덤uuid (36개의 문자: 8-4-4-12)생성
=end
def query_two_bits(device_token)
  payload = {
    'device_token' => device_token,
    'timestamp' => (Time.now.to_f * 1000).to_i,
    'transaction_id' => SecureRandom.uuid
  }

  # HTTP 헤더(인증 필드)에서 이 jwt_token를 사용
  response = HTTP.auth("Bearer #{jwt_token}").post(settings.query_url, json: payload)

  # 애플서버에 등록된 bit 정보가 없다면, json 대신 'Bit State Not Found' string 반환
  # 애플서버에 등록된 bit 정보가 있다면, 아래와 같이 리턴
  # { "bit0":false, "bit1":false, "last_update_time":"2018-10" }
end

# 장치의 2beat 쿼리 (상태) 업데이트 함수
def update_two_bits(device_token, bit_zero, bit_one)

  #body생성
  payload = {
    'device_token' => device_token,
    'timestamp' => (Time.now.to_f * 1000).to_i,
    'transaction_id' => SecureRandom.uuid,
    'bit0': bit_zero,
    'bit1': bit_one
  }

  response = HTTP.auth("Bearer #{jwt_token}").post(settings.update_url, json: payload)
  # Apple will return status 200 with blank response body if the update is successful
  # 업데이트 성공시 status: 200을 반환한다.
end