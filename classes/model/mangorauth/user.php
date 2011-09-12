<?php
class Model_MangoRauth_User extends Mango {

	protected $_fields = array(
		'username'	=> array(
	 	    'type'		=> 'string',
	 	    'required'	=> TRUE,
	 	    'min_length'=> 4,
	 	    'max_length'=> 127,
			'unique'	=> TRUE,
		),
		'password'	=> array(
	 	    'type'		=> 'string',
	 	    'required'	=> TRUE,
	 	    'min_length'=> 4,
	 	    'max_length'=> 127,
	 	    'rules'		=> array(
	 			'alpha_numeric' => NULL
			)
		),
		'email'		=> array(
			'type'		=> 'email',
			'required'	=> TRUE,
			'unique'	=> TRUE
		),
		'is_active'	=> array(
			'type'		=> 'boolean',
			'required'	=> TRUE
		),
		'logins'	=> array(
			'type'		=> 'int'
		),
		'last_login'=> array(
			'type'		=> 'int'
		)
	);

	protected $_relations = array(
		'tokens' => array('type'=>'has_many', 'model'=> 'mangorauth_user_token')
	);

	public function unique_key($value)
	{
		return Valid::email($value) ? 'email' : 'username';
	}

	public function create_user()
	{
		$this->password = $this->hash($this->password);
		return parent::create();
	}

	public function hash($password)
	{
		return MangoRauth::instance($this->_model)->hash_password($password);
	}

}