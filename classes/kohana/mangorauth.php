<?php defined('SYSPATH') OR die('No direct access allowed.');

class Kohana_MangoRauth {
	
	// Auth instances
	protected static $_instances = array();

	/**
	 * Singleton pattern
	 *
	 * @return MangoRauth
	 */
	public static function instance($config_entry = NULL)
	{
		if ( ! $config_entry)
		{
			$config_entry = 'default';
		}

		if ( ! isset(MangoRauth::$_instances[$config_entry]))
		{
			// Load the configuration for this type
			$config = Kohana::$config->load('mangorauth.'.$config_entry);

			$config['entry'] = $config_entry;

			Fire::log($config, 'CONFIG');
			// Create a new rauth instance
			MangoRauth::$_instances[$config_entry] = new MangoRauth($config);
		}

		return MangoRauth::$_instances[$config_entry];
	}

	/**
	 * Create an instance of MangoRauth.
	 *
	 * @return  rAuth
	 */
	public static function factory($config = array())
	{
		return new MangoRauth($config);
	}
	
	protected $_session;
	
	protected $_config;
	
	/**
	 * Loads Session and configuration options.
	 *
	 * @return  void
	 */
	public function __construct($config = array())
	{
		// Clean up the salt pattern and split it into an array
		$config['salt_pattern'] = preg_split('/,\s*/', $config['salt_pattern']);

		// Check model name: it should be string and should not contain the model prefix
		if (isset($config['model_name']) AND is_string($config['model_name']))
			$config['model_name'] = str_ireplace('model_', '', strtolower($config['model_name']));
		else
			$config['model_name'] = 'user';

		// Save the config in the object
		$this->_config = $config;

		// Set token model name and check model existence
		$this->_config['token_model_name'] = $this->_config['model_name'].'_token';

		$model_class = 'Model_'.$this->_config['token_model_name'];

		if ($this->_config['autologin_cookie'] AND ! class_exists($model_class))
		{
			throw new Kohana_Exception ('Could not find token model class :name', array(':name' => $model_class));
		}

		$this->_session = Session::instance();
	}

	/**
	 * Gets the currently logged in user from the session.
	 * Returns NULL if no user is currently logged in.
	 *
	 * @return  mixed
	 */
	public function get_user()
	{
		if ($this->logged_in())
		{
			return $this->_session->get($this->_config['session_key']);
		}

		return FALSE;
	}
	
	/**
	 * Check if there is an active session. Optionally allows checking for a
	 * specific role.
	 *
	 * @param   string   role name
	 * @return  mixed
	 */
	public function logged_in()
	{
		$status = FALSE;

		// Get the user from the session
		$user = $this->_session->get($this->_config['session_key']);

		if ( ! is_object($user))
		{
			// Attempt auto login
			if ($this->auto_login())
			{
				// Success, get the user back out of the session
				$user = $this->_session->get($this->_config['session_key']);
			}
		}

		// check from DB if set in config
		if ($this->_config['strong_check'])
		{
			$user = $this->_get_object($user, TRUE);
		}

		if (is_object($user)
			AND is_subclass_of($user, 'Model_MangoRauth_User')
			AND $user->loaded()
			AND $user->is_active
		)
		{
			// Everything is okay so far
			$status = TRUE;
		}

		return $status;
	}

	/**
	 * Logs a user in, based on the rauth autologin Cookie.
	 *
	 * @return  boolean
	 */
	public function auto_login()
	{
		if ($token = Cookie::get($this->_config['autologin_cookie']))
		{
			// Load the token and user
			$token = Mango::factory($this->_config['token_model_name'], array(
				'token' => $token
			))->load();
			 
			if ($token->loaded() AND $token->user->loaded())
			{
				if ($token->expires >= time() AND $token->user_agent === sha1(Request::$user_agent))
				{
					// Save the token to create a new unique token
					$token->save();
						
					// Set the new token
					Cookie::set($this->_config['autologin_cookie'], $token->token, $token->expires - time());
						
					// Complete the login with the found data
					$this->_complete_login($token->user);

					// Automatic login was successful
					return TRUE;
				}

				// Token is invalid
				$token->delete();
			}
		}

		return FALSE;
	}
	
	/**
	 * Attempt to log in a user by using an Mango object and plain-text password.
	 *
	 * @param   string   username to log in
	 * @param   string   password to check against
	 * @param   boolean  enable autologin
	 * @return  boolean
	 */
	public function login($username, $password, $remember = FALSE)
	{
		if (empty($password))
			return FALSE;

		if (is_string($password))
		{
			// Get the salt from the stored password
			$salt = $this->find_salt($this->password($username));

			Fire::log($salt, 'LOGIN SALT');


			// Create a hashed password using the salt from the stored password
			$password = $this->hash_password($password, $salt);

			Fire::log($password, 'LOGIN PASSWORD');
		}

		return $this->_login($username, $password, $remember);
	}

	/**
	 * Finds the salt from a password, based on the configured salt pattern.
	 *
	 * @param   string  hashed password
	 * @return  string
	 */
	public function find_salt($password)
	{
		$salt = '';

		foreach ($this->_config['salt_pattern'] as $i => $offset)
		{
			// Find salt characters, take a good long look...
			$salt .= substr($password, $offset + $i, 1);
		}

		return $salt;
	}
	
	/**
	 * Perform a hash, using the configured method.
	 *
	 * @param   string  string to hash
	 * @return  string
	 */
	public function hash($str)
	{
		return hash($this->_config['hash_method'], $str);
	}
	
	/**
     * Creates a hashed password from a plaintext password, inserting salt
     * based on the configured salt pattern.
     *
     * @param   string  plaintext password
     * @return  string  hashed password string
     */
    public function hash_password($password, $salt = FALSE)
    {
    	if ($salt === FALSE)
    	{
    		// Create a salt seed, same length as the number of offsets in the pattern
    		$salt = substr($this->hash(uniqid(NULL, TRUE)), 0, count($this->_config['salt_pattern']));
    	}

    	// Password hash that the salt will be inserted into
    	$hash = $this->hash($salt.$password);

    	// Change salt to an array
    	$salt = str_split($salt, 1);

    	// Returned password
    	$password = '';

    	// Used to calculate the length of splits
    	$last_offset = 0;

    	foreach ($this->_config['salt_pattern'] as $offset)
    	{
    		// Split a new part of the hash off
    		$part = substr($hash, 0, $offset - $last_offset);

    		// Cut the current part out of the hash
    		$hash = substr($hash, $offset - $last_offset);

    		// Add the part to the password, appending the salt character
    		$password .= $part.array_shift($salt);

    		// Set the last offset to the current offset
    		$last_offset = $offset;
    	}

    	// Return the password, with the remaining hash appended
    	return $password.$hash;
    }
    
    /**
     * Get the stored password for a username.
     *
     * @param   mixed   $user   username
     * @return  string
     */
    public function password($user)
    {
    	// Make sure we have a user object
    	$user = $this->_get_object($user);

    	return $user->password;
    }
    
    /**
     * Log out a user by removing the related session variables.
     *
     * @param   boolean  completely destroy the session
     * @param	boolean  remove all tokens for user
     * @return  boolean
     */
    public function logout($destroy = FALSE, $logout_all = FALSE)
    {
    	if ($token = Cookie::get($this->_config['autologin_cookie']))
    	{
    		// Delete the autologin Cookie to prevent re-login
    		Cookie::delete($this->_config['autologin_cookie']);

    		// Clear the autologin token from the database
    		$token = Mango::factory($this->_config['token_model_name'], array('token' => $token))->load();

    		if ($token->loaded() AND $logout_all)
    		{
    			// check and delete
    			$tokens = Mango::factory($this->_config['token_model_name'], array(
    				'user_id'	=> $token->user->_id
    			))->load(FALSE);
    			
    			foreach($tokens as $token)
    			{
    				$token->delete();
    			}
    		}
    		elseif ($token->loaded())
    		{
    			$token->delete();
    		}
    	}

    	if ($destroy === TRUE)
    	{
    		// Destroy the session completely
    		$this->_session->destroy();
    	}
    	else
    	{
    		// Remove the user from the session
    		$this->_session->delete($this->_config['session_key']);

    		// Regenerate session_id
    		$this->_session->regenerate();
    	}

    	// Double check
    	return ! $this->logged_in();
    }
    
    /**
     * Convert a unique identifier string to a user object
     *
     * @param mixed $user
     * @param   bool    $strong_check   TRUE to force checking existence in DB
     * @return Model_User
     */
    protected function _get_object($user, $strong_check = FALSE)
    {
    	$name = $this->_config['entry'];
    	static $current;

    	//make sure the user is loaded only once.
    	if ( ! is_object($current[$name]) AND is_string($user))
    	{
    		// Load the user
    		$current[$name] = Mango::factory($this->_config['model_name']);
    		$current[$name] = Mango::factory($this->_config['model_name'], array($current[$name]->unique_key($user), $user))->load();
    	}

    	if (is_object($user) AND is_subclass_of($user, 'Model_Rauth_User') AND $user->loaded())
    	{
    		if ($strong_check)
    		{
    			$current[$name] = Mango::factory($this->_config['model_name'], array(
    				'_id'		=> $user->_id,
    				'username'	=> $user->username
    			))->load();
    		}
    		else
    		{
    			$current[$name] = $user;
    		}
    	}

    	return $current[$name];
    }

    /**
     * Logs a user in.
     *
     * @param   string   username
     * @param   string   password
     * @param   boolean  enable auto-login
     * @return  boolean
     */
    protected function _login($user, $password, $remember)
    {
    	// Make sure we have a user object
    	$user = $this->_get_object($user);

    	// If the passwords match, perform a login
    	if ($user->is_active AND $user->password === $password)
    	{
    		if ($remember === TRUE AND $this->_config['autologin_cookie'])
    		{
    			$token = Mango::factory($this->_config['token_model_name'], array(
					'user_id'	=> $user->_id,
    				'expires'	=> time() + $this->_config['lifetime'],
					'user_agent'=> sha1(Request::$user_agent),
					'created'	=> time(),
				))->create_token();

    			// Set the autologin Cookie
    			Cookie::set($this->_config['autologin_cookie'], $token->token, $this->_config['lifetime']);
    		}

    		// Finish the login
    		$this->_complete_login($user);
    		 
    		return TRUE;
    	}

    	// Login failed
    	return FALSE;
    }

    /**
     * Complete the login for a user by incrementing the logins and setting
     * session data: user_id, username, roles
     *
     * @param   object   user model object
     * @return  void
     */
    protected function _complete_login($user)
    {
    	// Update the number of logins and the last login date
    	// $user->complete_login();

    	// Regenerate session_id
    	$this->_session->regenerate();

    	// Store username in session
    	$this->_session->set($this->_config['session_key'], $user);

    	return TRUE;
    }
}