class UsersController < ApplicationController
	skip_before_action :authenticate_request, only: %i[login register]


    def login
    	authenticate params[:email], params[:password]
  	end
  	def test
    	render json: {
          message: 'You have passed authentication and authorization test'
        }
 	end

	def register
		@user = User.create(user_params)
		if @user.save
			response = {message: "User registered"}
			render json: response, status: :created
		else
			render json: @user.errors, status: :bad
		end
	end

	private
	def authenticate(email, password)
	    command = AuthenticateUser.call(email, password)

	    if command.success?
	      render json: {
	        access_token: command.result,
	        message: 'Login Successful'
	      }
	    else
	      render json: { error: command.errors }, status: :unauthorized
	    end
    end
	def user_params
		params.permit(:name,:email,:password)
	end
end
