<?php
/*
Plugin Name: GodAuth SSO Authentication
Version: 1.0
Plugin URI: http://github.iamcal.com
Description: Authenticate users using GodAuth SSO
Author: Cal Henderson
Author URI: http://iamcal.com
*/

class GodAuthAuthenticationPlugin {

	#
	# To use this plugin with a different SSO system, modify these functions
	# to return the current username and email address and a logout URL.
	#

	function sso_user(){	return $_ENV['GodAuth_User']; }
	function sso_email(){	return $_ENV['GodAuth_User'].'@mydomain.com' }
	function sso_logout(){	return 'http://sso.mydomain.com/logout/'; }


	#
	# constructor
	#

	function GodAuthAuthenticationPlugin() {

		add_filter('login_url', array(&$this, 'bypass_reauth'));
		add_filter('show_password_fields', array(&$this, 'disable'));
		add_filter('allow_password_reset', array(&$this, 'disable'));
		add_action('check_passwords', array(&$this, 'generate_password'), 10, 3);
		add_action('wp_logout', array(&$this, 'logout'));
	}


	#
	# filters & actions
	#

	function bypass_reauth($login_url){

		return remove_query_arg('reauth', $login_url);
	}

	function disable($flag){

		return false;
	}

	function generate_password($username, $password1, $password2){

		$password1 = $password2 = wp_generate_password();
	}

	function logout(){

		header('Location: '.$this->sso_logout());
		exit;
	}


	#
	# the guts
	#

	function check_remote_user(){

		$username = $this->sso_user();

		if (!$username){
			return new WP_Error('empty_username', 'No REMOTE_USER or REDIRECT_REMOTE_USER found.');
		}

		$user = get_userdatabylogin($username);
		if (!$user){
			$password = wp_generate_password();
			$email = $this->sso_email();

			require_once(WPINC . DIRECTORY_SEPARATOR . 'registration.php');

			$user_id = wp_create_user($username, $password, $email);
			$user = get_user_by('id', $user_id);
		}

		return $user;
	}
}

$godauth_authentication_plugin = new GodAuthAuthenticationPlugin();

// Override pluggable function to avoid ordering problem with 'authenticate' filter
if (!function_exists('wp_authenticate')){
	function wp_authenticate($username, $password){
		global $godauth_authentication_plugin;

		$user = $godauth_authentication_plugin->check_remote_user();
		if (!is_wp_error($user)){
			$user = new WP_User($user->ID);
		}

		return $user;
	}
}

?>
