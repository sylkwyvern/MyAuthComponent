<?php
/**
 * Extended Authentication Component
 * 
 * This component is derived from the CakePHP's standard AuthComponent
 * and adds so-called "remember me feature" to the base class.
 * 
 * You can simply use this component as substitute for the AuthComponent.
 * Only two things are needed along with this component as follows:
 * 
 *   (1) Special table named 'auto_logins'.
 *   (2) Check box named 'rememberme' on your login form.
 * 
 * The 'auto_logins' table is something like this:
 *   create table auto_logins (
 *     id                int(11) not null auto_increment primary key,
 *     user_id           int(11),
 *     expires           datetime,
 *     token             varchar(64),
 *     created           datetime,
 *     modified          datetime
 *   );
 *   alter table auto_logins add index (token);
 *   alter table auto_logins add index (expires);
 * 
 * This component doesn't save any user information in cookies.
 * It saves the information in the 'auto_logins' table.
 * 
 * @author Gen Yoshida
 *
 */

App::import('Component', 'Auth');

class MyAuthComponent extends AuthComponent {

	var $checkBoxName = 'rememberme';
	var $cookieName = 'autoLogin';
	var $myModelName = 'AutoLogin';
	var $expires = '+2 weeks';

	// overridden
	function __construct(){
		// Add the CookieComponent.
		$this->components[] = 'Cookie';
		parent::__construct();
	}

	// overridden
	function initialize(&$controller, $settings = array()){
		parent::initialize($controller, $settings);
		// Hold a reference to the controller.
		$this->Controller =& $controller;
	}

	// overridden
	function logout() {
		self::_clearLoginState();
		return parent::logout();
	}

	// overridden
	function login($data = null) {
		// Clean up the auto_logins table.
		self::_deleteAllExpiredRecords();

		$loggedIn = parent::login($data);

		$model =& $this->getModel();
		if (isset($this->Controller->data[$model->alias][$this->checkBoxName])) {
			// The user wants to keep the login state.
			self::_keepLoginState();
		} else {
			// The user doesn't want to keep the login state.
			self::_clearLoginState();
		}

		return $loggedIn;
	}

	// overridden
	function user($key = null) {
		$recUser = parent::user($key);

		if (empty($recUser)) {
			// The session is NOT alive.
			$token = $this->Cookie->read($this->cookieName);
			if (!empty($token)) {
				$autoLogin =& $this->getModel($this->myModelName);
				$conditions = array(
					'token' => $token,
					'expires > '=> date('Y-m-d H:i:s'),
				);
				$userId = $autoLogin->field('user_id', $conditions);
				if (empty($userId)) {
					// The expiration date has passed.
					// (Or the record has been deleted due to a bug.)
					self::_clearLoginState();
				} else {
					if (parent::login($userId)) {
						$recUser = $this->Session->read($this->sessionKey);
					}
				}
			}
		} else {
			// The session is alive. In this case, the expiration date in the
			// auto_logins table is ignored.
			// New expiration date will be set to 2 weeks later.
			$token = $this->Cookie->read($this->cookieName);
			// Generate a new token and extend the expiration data.
			self::_keepLoginState($token);
		}

		return $recUser;
	}


	//
	// Generate a new token or update the old token and save it into the table.
	//
	function _keepLoginState($token = null) {
		$user = $this->Session->read($this->sessionKey);
		if (empty($user)) {
			return false;
		}

		$modelUser =& $this->getModel();
		$userId = $user['id'];
		
		$autoLogin =& $this->getModel($this->myModelName);

		$id = null;
		if (!empty($token)) {
			$conditions = array(
				'token' => $token,
//				'expires > '=> date('Y-m-d H:i:s'),
			);
			$id = $autoLogin->field('id', $conditions);
		}

		// Add or update the record of the auto_logins table.
		$newToken = self::_saveAutoLoginRecord($id, $userId);

		// Save the generated token into the cookie.
		$this->Cookie->write($this->cookieName, $newToken, true, $this->expires);

		return true;
	}



	//
	// Delete the record of auto_logins table and the cookie.
	//
	function _clearLoginState() {
		$token = $this->Cookie->read($this->cookieName);
		if (!empty($token)) {
			$autoLogin =& $this->getModel($this->myModelName);
			$autoLogin->deleteAll(array('token' => $token));
			$this->Cookie->delete($this->cookieName);
		}
	}

	//
	// Add or update the record of the auto_logins table.
	//
	function _saveAutoLoginRecord($id, $userId) {
		$autoLogin =& $this->getModel($this->myModelName);

		$tokenBase = array(mt_rand(), mt_rand() => mt_rand());
		$token = Security::hash(serialize($tokenBase), null, true);

		$recAutoLogin = array(
			$this->myModelName => array(
				'id' => $id,
				'user_id' => $userId,
				'token' => $token,
				'expires' => date('Y-m-d H:i:s', strtotime($this->expires)),
			)
		);
		if (empty($id)) {
			$autoLogin->create();
		}
		$autoLogin->save($recAutoLogin);

		return $token;
	}

	function _deleteAllExpiredRecords() {
		$autoLogin =& $this->getModel($this->myModelName);
		$conditions = array(
			'expires <= '=> date('Y-m-d H:i:s'),
		);
		$autoLogin->deleteAll($conditions);
	}
}
