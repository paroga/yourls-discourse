<?php
/*
Plugin Name: Discourse Login
Plugin URI: https://github.com/paroga/yourls-discourse
Description: A Plugin to use Discourse as SSO provider for the admin interface
Version: 1.0
Author: paroga
Author URI: http://paroga.com
*/

// No direct call
if (!defined('YOURLS_ABSPATH')) die();

define('DISCOURSE_URL', getenv('DISCOURSE_URL'));
define('DISCOURSE_SSO_SECRET', getenv('DISCOURSE_SSO_SECRET') || file_get_contents(getenv('DISCOURSE_SSO_SECRET_FILE')));
define('YOURLS_NO_HASH_PASSWORD', true);


yourls_add_filter('logout', 'discourse_logout');

function discourse_logout()
{
    session_destroy();
}


yourls_add_filter('is_valid_user', 'discourse_is_valid_user');

function discourse_is_valid_user($unfiltered_valid)
{
    if (isset($_SESSION['discourse'])) {
        yourls_set_user($_SESSION['discourse']['username']);
        return true;
    }

    $nonce = hash('sha512', mt_rand() . time());
    $payload = base64_encode(http_build_query(
        array(
            'nonce' => $nonce,
            'return_sso_url' => yourls_admin_url()
        )
    ));
    $request = array(
        'sso' => $payload,
        'sig' => hash_hmac('sha256', $payload, DISCOURSE_SSO_SECRET)
    );
    $query = http_build_query($request);
    $_SESSION['discourse_nonce'] = $nonce;
    header('Cache-Control: no-cache, no-store, max-age=0, must-revalidate');
    header("Location: " . DISCOURSE_URL . "/session/sso_provider?$query");
    exit;
}


yourls_add_filter('shunt_is_valid_user', 'discourse_shunt_is_valid_user');

function discourse_shunt_is_valid_user()
{
    session_start();

    if (isset($_SERVER['REQUEST_URI']) && preg_match('/\/admin\/plugins\.php.*/', $_SERVER['REQUEST_URI'])) {
        if (!isset($_SESSION['discourse']) || $_SESSION['discourse']['admin'] != true) {
            yourls_redirect(yourls_admin_url('?access=denied'), 302);
        }
    }

    if (!isset($_GET['sso']) && !isset($_GET['sig'])) {
        return null;
    }

    $sso = $_GET['sso'];
    $sig = $_GET['sig'];
    // validate sso
    if (hash_hmac('sha256', urldecode($sso), DISCOURSE_SSO_SECRET) !== $sig) {
        yourls_e('Invalid signature from Discourse');
        return false;
    }
    $query = array();
    parse_str(base64_decode(urldecode($sso)), $query);
    // verify nonce with generated nonce
    $nonce = $_SESSION['discourse_nonce'];
    unset($_SESSION['discourse_nonce']);
    if ($query['nonce'] != $nonce) {
        yourls_e('Invalid nonce from Discourse' . $nonce);
        return false;
    }

    $_SESSION['discourse'] = $query;
    yourls_redirect(yourls_admin_url(''), 302);
}
