class JsonWebToken
# our secret key to encode our jwt

  class << self
    def encode(payload, exp = 2.hours.from_now)
      # set token expiration time 
      payload[:exp] = exp.to_i
      
       # this encodes the user data(payload) with our secret key
       secret = 'my_secret_key'
     JWT.encode(payload, secret, 'HS256')
      #JWT.encode(payload, Rails.application.secrets.secret_key_base)
    end

    def decode(token)
      #decodes the token to get user data (payload)
      secret = 'my_secret_key'
     body = JWT.decode(token, secret, true, { :algorithm => 'HS256' })[0]
     #body = JWT.decode(token, Rails.application.secrets.secret_key_base)[0]
      HashWithIndifferentAccess.new body

    # raise custom error to be handled by custom handler
    rescue JWT::ExpiredSignature, JWT::VerificationError => e
      raise ExceptionHandler::ExpiredSignature, e.message
    rescue JWT::DecodeError, JWT::VerificationError => e
      raise ExceptionHandler::DecodeError, e.message
    end
  end
end