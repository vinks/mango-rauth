<?php

class Model_MangoRauth_User_Token extends Mango {

	protected $_fields = array(
		'user_agent'=> array(
			'type'		=> 'string',
			'required'	=> TRUE,
	 	    'max_length'=> 40,
		),
	 	'token'		=> array(
	 	    'type'		=> 'string',
	 	    'required'	=> TRUE,
	 	    'max_length'=> 40,
			'unique'	=> TRUE,
		),
		'created'	=> array(
			'type'		=> 'int',
			'required'	=> TRUE
		),
		'expires'	=> array(
			'type'		=> 'int',
			'required'	=> TRUE
		),
	);

	protected $_relations = array(
		'user'    => array('type'=>'belongs_to', 'model'=>'mangorauth_user'),
	);

	public function create_token()
	{
		$this->token = $this->prepare_token();
		return parent::create();
	}

	protected function prepare_token()
	{
		do
		{
			$token = sha1(uniqid(Text::random('alnum', 32), TRUE));
		}
		while(Mango::factory($this->_model, array('token' => $token))->loaded());

		return $token;
	}
}