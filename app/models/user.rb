class User < ApplicationRecord
  validates :password_digest, :user_name, :session_token, presence: true
  validates :password, length: { minimum: 6, allow_nil: true }

  attr_reader :password
  before_validation :ensure_session_token

  def self.find_by_credentials(user_name, password)
    user = User.find_by(user_name: user_name)
    return nil unless user
    return user if user.is_password?(password)
  end

  def reset_session_token!
    self.session_token = SecureRandom::urlsafe_base64
    self.save!
    self.session_token
  end

  def password=(password)
    @password = password
    self.password_digest = BCrypt::Password.create(password)
  end

  def is_password?(password)
    BCrypt::Password.new(self.password_digest).is_password?(password)
  end

  def ensure_session_token
    self.session_token ||= reset_session_token!
  end


end
