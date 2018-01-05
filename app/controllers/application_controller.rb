class ApplicationController < ActionController::Base
  # protect_from_forgery with: :exception
  helper_method :current_user, :logged_in?

  def login(user)
    session[:session_token] = user.reset_session_token!
  end

  def logout
    current_user.reset_session_token!
    session[:session_token] = nil
  end

  def logged_in?
    !!current_user
  end

  def require_no_user!
    redirect_to cats_url if current_user
  end

  def require_login
    redirect_to new_session_url unless logged_in?
  end

  def current_user
    session_cookie = session[:session_token]
    return nil unless session_cookie
    @current_user ||= User.find_by(session: session_cookie)
  end

end