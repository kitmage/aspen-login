<?php
/**
 * Plugin Name: Aspen Intended Login
 * Description: Persists and honors intended front-end URLs across Force Login, WordPress login, FluentAuth, and FluentForms registration flows.
 * Version: 1.0.0
 * Author: Aspen
 * License: GPL-2.0-or-later
 * Text Domain: aspen-intended-login
 */

if (!defined('ABSPATH')) {
    exit;
}

define('ASPEN_INTENDED_COOKIE', 'aspen_intended_path');
define('ASPEN_INTENDED_TTL', 15 * MINUTE_IN_SECONDS);

/**
 * Sanitize an intended destination into a safe on-site path with optional query.
 *
 * @param mixed $value Candidate redirect destination.
 * @return string Safe relative path and query, or an empty string when invalid.
 */
function aspen_sanitize_intended_path($value) {
    if (empty($value) || !is_string($value)) {
        return '';
    }

    $value = trim(wp_unslash($value));

    if (preg_match('~^https?://~i', $value)) {
        $host = parse_url($value, PHP_URL_HOST);
        $home_host = parse_url(home_url(), PHP_URL_HOST);

        if ($host && $home_host && strtolower($host) !== strtolower($home_host)) {
            return '';
        }

        $path = parse_url($value, PHP_URL_PATH) ?: '';
        $query = parse_url($value, PHP_URL_QUERY);
        $value = $path . ($query ? ('?' . $query) : '');
    }

    if (!str_starts_with($value, '/')) {
        $value = '/' . ltrim($value, '/');
    }

    $only_path = parse_url($value, PHP_URL_PATH) ?: $value;
    $lower_path = strtolower($only_path);
    $blocked_prefixes = [
        '/wp-login.php',
        '/wp-admin',
        '/wp-includes',
        '/wp-content',
    ];

    foreach ($blocked_prefixes as $prefix) {
        if (str_starts_with($lower_path, $prefix)) {
            return '';
        }
    }

    if (str_contains($lower_path, 'admin-ajax.php')) {
        return '';
    }

    if (preg_match('~\.(png|jpg|jpeg|gif|svg|webp|ico|css|js|map|pdf|zip)$~i', $only_path)) {
        return '';
    }

    return esc_url_raw($value);
}

/**
 * Determine the cookie domain used for intended URL persistence.
 *
 * @return string Cookie domain.
 */
function aspen_intended_cookie_domain() {
    return parse_url(home_url(), PHP_URL_HOST) ?: '';
}

/**
 * Set the intended destination cookie.
 *
 * @param string $path_value Safe relative path and query.
 */
function aspen_set_intended_cookie($path_value) {
    setcookie(
        ASPEN_INTENDED_COOKIE,
        $path_value,
        [
            'expires'  => time() + ASPEN_INTENDED_TTL,
            'path'     => '/',
            'domain'   => aspen_intended_cookie_domain(),
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]
    );

    $_COOKIE[ASPEN_INTENDED_COOKIE] = $path_value;
}

/**
 * Clear the intended destination cookie.
 */
function aspen_clear_intended_cookie() {
    setcookie(
        ASPEN_INTENDED_COOKIE,
        '',
        [
            'expires'  => time() - HOUR_IN_SECONDS,
            'path'     => '/',
            'domain'   => aspen_intended_cookie_domain(),
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]
    );

    unset($_COOKIE[ASPEN_INTENDED_COOKIE]);
}

/**
 * Check whether a request URI should never be stored as an intended destination.
 *
 * @param string $uri Request URI.
 * @return bool
 */
function aspen_is_excluded_intended_uri($uri) {
    $path = parse_url($uri, PHP_URL_PATH) ?: $uri;
    $path = '/' . ltrim(strtolower($path), '/');

    $excluded_prefixes = [
        '/wp-login.php',
        '/wp-admin',
        '/wp-includes',
        '/wp-content',
        '/register',
        '/continue',
        '/login',
    ];

    foreach ($excluded_prefixes as $prefix) {
        if (str_starts_with($path, $prefix)) {
            return true;
        }
    }

    return str_contains($path, 'admin-ajax.php');
}

/**
 * Store intended path for logged-out GET requests to front-end pages.
 */
function aspen_store_intended_path() {
    if (is_user_logged_in()) {
        return;
    }

    if (!empty($_GET['ff_landing']) || !empty($_GET['entry_confirmation'])) {
        return;
    }

    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
        return;
    }

    $uri = $_SERVER['REQUEST_URI'] ?? '';
    if (!$uri || aspen_is_excluded_intended_uri($uri)) {
        return;
    }

    $intended = aspen_sanitize_intended_path($uri);
    if ($intended) {
        aspen_set_intended_cookie($intended);
    }
}
add_action('init', 'aspen_store_intended_path');

/**
 * Force register links to the public registration page and preserve redirect_to.
 *
 * @param string $register_url Default register URL.
 * @return string
 */
function aspen_register_url($register_url) {
    $register = home_url('/register/');
    $candidate = $_REQUEST['redirect_to'] ?? ($_COOKIE[ASPEN_INTENDED_COOKIE] ?? '');
    $path = aspen_sanitize_intended_path($candidate);

    if ($path) {
        return add_query_arg('redirect_to', home_url($path), $register);
    }

    return $register;
}
add_filter('register_url', 'aspen_register_url');

/**
 * Prefer requested redirects or the stored intended path after login.
 *
 * @param string   $redirect_to           Default redirect URL.
 * @param string   $requested_redirect_to Requested redirect URL.
 * @param WP_User  $user                  Logged-in user.
 * @return string
 */
function aspen_login_redirect($redirect_to, $requested_redirect_to, $user) {
    $candidate = $requested_redirect_to ?: ($_REQUEST['redirect_to'] ?? '');
    $path = aspen_sanitize_intended_path($candidate);

    if (!$path) {
        $path = aspen_sanitize_intended_path($_COOKIE[ASPEN_INTENDED_COOKIE] ?? '');
    }

    if ($path) {
        return home_url($path);
    }

    $fallback_path = aspen_sanitize_intended_path($redirect_to);
    return $fallback_path ? home_url($fallback_path) : home_url('/');
}
add_filter('login_redirect', 'aspen_login_redirect', 99999, 3);

/**
 * Consume the intended cookie from the /continue helper page.
 */
function aspen_continue_redirect() {
    if (!is_page('continue')) {
        return;
    }

    $candidate = $_GET['redirect_to'] ?? '';
    $path = aspen_sanitize_intended_path($candidate);

    if (!$path) {
        $path = aspen_sanitize_intended_path($_COOKIE[ASPEN_INTENDED_COOKIE] ?? '');
    }

    $target = $path ? home_url($path) : home_url('/');

    if (is_user_logged_in()) {
        aspen_clear_intended_cookie();
        wp_safe_redirect($target);
        exit;
    }

    wp_safe_redirect(wp_login_url(home_url('/continue/')));
    exit;
}
add_action('template_redirect', 'aspen_continue_redirect');

/**
 * Bypass Force Login for public authentication and FluentForms confirmation flows.
 *
 * @param bool   $bypass      Whether Force Login should be bypassed.
 * @param string $visited_url Visited URL.
 * @return bool
 */
function aspen_forcelogin_bypass($bypass, $visited_url) {
    if (is_page('register') || is_page('continue') || is_page('login')) {
        return true;
    }

    if (!empty($_GET['ff_landing']) || !empty($_GET['entry_confirmation'])) {
        return true;
    }

    return $bypass;
}
add_filter('v_forcelogin_bypass', 'aspen_forcelogin_bypass', 10, 2);

/**
 * Route WordPress login URLs to the public login page.
 *
 * @param string $login_url    Default login URL.
 * @param string $redirect     Redirect URL.
 * @param bool   $force_reauth Whether to force reauthentication.
 * @return string
 */
function aspen_login_url($login_url, $redirect, $force_reauth) {
    return home_url('/login/');
}
add_filter('login_url', 'aspen_login_url', 10, 3);

/**
 * Render a configurable registration button.
 *
 * @param array $atts Shortcode attributes.
 * @return string
 */
function aspen_register_button_shortcode($atts) {
    $atts = shortcode_atts(
        [
            'text'  => 'Register',
            'class' => 'register-button',
            'url'   => home_url('/register/'),
        ],
        $atts,
        'register_button'
    );

    return sprintf(
        '<a href="%s" class="%s">%s</a>',
        esc_url($atts['url']),
        esc_attr($atts['class']),
        esc_html($atts['text'])
    );
}
add_shortcode('register_button', 'aspen_register_button_shortcode');

/**
 * Render a logout link for the current user.
 *
 * @return string
 */
function aspen_logout_link_shortcode() {
    if (!is_user_logged_in()) {
        return '';
    }

    $user = wp_get_current_user();
    $logout_url = wp_logout_url(home_url('/'));

    return sprintf(
        '<a href="%s">%s</a>',
        esc_url($logout_url),
        esc_html(sprintf(__('Logout: %s', 'aspen-intended-login'), $user->display_name))
    );
}
add_shortcode('logout_link', 'aspen_logout_link_shortcode');
