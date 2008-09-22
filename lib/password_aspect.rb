# Provide Methods for Models which should have a Password
#
# The Models are expected to have fields "salt" and "hashed_password"
module PasswordAspect
  
    module ClassMethods
      # call-seq:
      #   trylogin(:email => String, :password => String) => User
      # 
      # Try to log in a user with email and password.
      # On success the user is returned, nil otherwise.
      def trylogin(attributes)
        p = attributes.delete :password
        u = self.find(:first, :limit => 1, :conditions => attributes)
        u.password = p
        u.authenticated? ? u : nil
      rescue ActiveRecord::RecordNotFound
        nil
      end
    end

    def self.included(model) # :nodoc:
       model.extend  ClassMethods
       model.class_eval do
         attr_protected :hashed_password, :salt
         attr_accessor  :password, :old_password, :security_token
         before_save :generate_salt_and_hashed_password
         validates_presence_of     :password, :if => :new_user?
         validates_confirmation_of :password
         validates_length_of       :password, :minimum => 6, :allow_nil => true
         validate                  :password_change_allowed
         before_create             :generate_salt
       end
    end
    
    # Wether the users provided password matches
    def authenticated?
      verify_password self.password
    end

    # Return a security token that can be sent via email and be
    # verified later.
    #
    # This is useful for password recovery emails or stuff like that
    #
    # The key can be used to generate different tokens for different purposes
    # In that case the check for a valid token has to be performed manually,
    # not via security_token_valid
    #--
    # TODO: Expire security token timebased
    def generate_security_token(key='')
      encrypt "cdslgsdim;#{salt}#{email}#{hashed_password}#{key}"
    end

    # Verify a security token provided earlier in the security_token attribute
    def security_token_valid?
      security_token == generate_security_token
    end

    # Check wether the users email is unique
    def email_unique?
      strip_email
      mail_owner = User.find_by_email(self.email)
      mail_owner.nil? || mail_owner.id == self.id
    end

  protected

    # The encryption algorithm.
    # Overwrite this if you need something different, e.g. cleartext
    # passwords for debugging purposes or stronger encryption.
    # Defaults to SHA256 Hexdigest
    def encrypt(str)
      Digest::SHA256.hexdigest(str)
    end

    # Sets this records salt
    def generate_salt
      self.salt = encrypt("--#{Time.now.to_s}--#{email}--")
    end

    # Sets this records salt and hashed password
    def generate_salt_and_hashed_password
      unless self.password.nil?
        generate_salt
        self.hashed_password = encrypt("#{self.password}#{self.salt}")
      end
    end

    # Tell wether an attempt to change the password should be allowed
    # 
    # Requires the model to either have a valid security token set
    # (from a password recovery email for example, see generate_security_token)
    # or the old password correctly set
    def password_change_allowed
      if changing_password? && !security_token_valid? && !verify_password(self.old_password)
        errors.add :security_token, "Incorrect"
        errors.add :old_password, "Incorrect"
      end
    end

    # Discern wether we're trying to change a password on an existing user or
    # setting a password on new user
    def changing_password?
      !self.password.nil? && !new_user?
    end

    # Check if a password is correct for this user
    def verify_password(pw)
      self.hashed_password == encrypt("#{pw}#{self.salt}")
    end

    # Tell wether a user is a new user or not
    #
    # A new user is a user without a hashed password
    def new_user?
      hashed_password.blank?
    end

    def strip_email # :nodoc:
      self.email = self.email.strip.downcase unless self.email.nil?
    end
end