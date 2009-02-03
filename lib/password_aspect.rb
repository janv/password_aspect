# Provide Methods for Models which should have a Password
#
# The Models are expected to have fields "salt" and "hashed_password"
module PasswordAspect
  
    module ClassMethods
      # call-seq:
      #   trylogin(:email => String, :password => String) => User
      # 
      # Versuche User mit den attributen email und password anzumelden
      # Bei Erfolg wird ein User zurückgegeben, bei Misserfolg nil
      def trylogin(attributes)
        p = attributes.delete :password
        u = self.find(:first, :limit => 1, :conditions => attributes)
        u.password = p
        u.authenticated? ? u : nil
      rescue ActiveRecord::RecordNotFound, NoMethodError
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
         validates_length_of       :password, :minimum => 6, :allow_nil => true, :if => :changing_password?
         validate                  :password_change_allowed
         before_create             :generate_salt
       end
    end
    
    def authenticated?
      verify_password self.password
    end

    def generate_security_token(key='')
      encrypt "cdslgsdim;#{salt}#{email}#{hashed_password}#{key}"
    end

    def set_correct_token(k='')
      self.security_token = generate_security_token(k)
    end

    def security_token_valid?(k='')
      security_token == generate_security_token(k)
    end

    def email_unique?
      strip_email
      mail_owner = User.find_by_email(self.email)
      mail_owner.nil? || mail_owner.id == self.id
    end

  protected

    def encrypt(str)
      Digest::SHA256.hexdigest(str)
    end

    def generate_salt
      self.salt = encrypt("--#{Time.now.to_s}--#{email}--")
    end

    def generate_salt_and_hashed_password
      unless self.password.blank?
        generate_salt
        self.hashed_password = encrypt("#{self.password}#{self.salt}")
      end
    end

    def password_change_allowed
      if changing_password? && !security_token_valid? && !verify_password(self.old_password)
        errors.add :security_token, "Incorrect"
        errors.add :old_password, "Incorrect"
      end
    end

    # Eine Passwortänderung liegt vor, wenn passwort gesetzt ist und
    # es sich nicht um einen neuen User handelt
    def changing_password?
      #password not blank and existing user
      !self.password.blank? && !new_user?
    end

    def verify_password(pw)
      self.hashed_password == encrypt("#{pw}#{self.salt}")
    end

    # Sagt ob es sich um einen neuen User handelt
    #
    # Wenn kein hashed_password existiert muss es sich um einen neuen User
    # oder um einen Unshadow User handeln
    def new_user?
      hashed_password.blank?
    end

    def strip_email
      self.email = self.email.strip.downcase unless self.email.nil?
    end
end