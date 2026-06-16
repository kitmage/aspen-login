Here's the base snippet:
```php
/**
 * Aspen: Persist and honor the "intended" URL across Force Login + wp-login + FluentAuth + FluentForms registration.
 *
 * Strategy:
 * - Store ONLY a relative path+query (e.g. "/red/?x=1") in a short-lived cookie.
 * - Never allow redirect targets to wp-admin/wp-includes/wp-content or file-like assets.
 * - /continue consumes the cookie and clears it.
 */

define('ASPEN_INTENDED_COOKIE', 'aspen_intended_path');
define('ASPEN_INTENDED_TTL', 15 * MINUTE_IN_SECONDS);

/**
 * Sanitize an "intended" destination into a safe on-site PATH (with optional query), e.g. "/red/?x=1".
 * Returns '' if invalid.
 */
function aspen_sanitize_intended_path($value) {
    if (empty($value) || !is_string($value)) {
        return '';
    }

    $value = trim($value);

    // If someone hands us a full URL, reduce it to path + query.
    if (preg_match('~^https?://~i', $value)) {
        $p = parse_url($value, PHP_URL_PATH) ?: '';
        $q = parse_url($value, PHP_URL_QUERY);
        $value = $p . ($q ? ('?' . $q) : '');
    }

    // Normalize to leading slash.
    if (!str_starts_with($value, '/')) {
        $value = '/' . ltrim($value, '/');
    }

    // Block internal endpoints and common "wrong target" areas.
    $blocked_prefixes = [
        '/wp-login.php',
        '/wp-admin',
        '/wp-includes',
        '/wp-content',
    ];
    foreach ($blocked_prefixes as $prefix) {
        if (str_starts_with($value, $prefix)) {
            return '';
        }
    }

    // Block file-like redirects (assets/documents).
    $only_path = parse_url($value, PHP_URL_PATH) ?: $value;
    if (preg_match('~\.(png|jpg|jpeg|gif|svg|webp|ico|css|js|map|pdf|zip)$~i', $only_path)) {
        return '';
    }

    return $value;
}

/**
 * Set / clear cookie helper (ensures consistent domain/flags).
 */
function aspen_set_intended_cookie($path_value) {
    $domain = parse_url(home_url(), PHP_URL_HOST);

    setcookie(
        ASPEN_INTENDED_COOKIE,
        $path_value,
        [
            'expires'  => time() + ASPEN_INTENDED_TTL,
            'path'     => '/',
            'domain'   => $domain,
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]
    );
}

function aspen_clear_intended_cookie() {
    $domain = parse_url(home_url(), PHP_URL_HOST);

    setcookie(
        ASPEN_INTENDED_COOKIE,
        '',
        [
            'expires'  => time() - 3600,
            'path'     => '/',
            'domain'   => $domain,
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]
    );
}

/**
 * 1) Store intended PATH for logged-out requests to front-end pages.
 */
add_action('init', function () {
    if (is_user_logged_in()) {
        return;
    }

    // Don't store intended for special FluentForms confirmation flows
    if (!empty($_GET['ff_landing']) || !empty($_GET['entry_confirmation'])) {
        return;
    }

    $uri = $_SERVER['REQUEST_URI'] ?? '';
    if (!$uri) {
        return;
    }

    // Avoid storing admin/login/internal endpoints or assets
    if (
        str_starts_with($uri, '/wp-login.php') ||
        str_starts_with($uri, '/wp-admin') ||
        str_starts_with($uri, '/wp-includes') ||
        str_starts_with($uri, '/wp-content') ||
        str_contains($uri, 'admin-ajax.php')
    ) {
        return;
    }

// Avoid storing your public auth/registration/helper pages as "intended"
if (
    str_starts_with($uri, '/register') ||
    str_starts_with($uri, '/continue') ||
    str_starts_with($uri, '/login')
) {
    return;
}

    // Only store GET navigations
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
        return;
    }

    $intended = aspen_sanitize_intended_path($uri);
    if (!$intended) {
        return;
    }

    aspen_set_intended_cookie($intended);
});

/**
 * 2) Force the Register button/link to go to /register and preserve redirect_to.
 */
add_filter('register_url', function ($register_url) {
    $register = home_url('/register/');

    $candidate = $_REQUEST['redirect_to'] ?? ($_COOKIE[ASPEN_INTENDED_COOKIE] ?? '');
    $path = aspen_sanitize_intended_path($candidate);

    if ($path) {
        // pass an absolute URL for compatibility with various flows
        return add_query_arg('redirect_to', home_url($path), $register);
    }

    return $register;
});

/**
 * 3) After login (and after FluentAuth verification), prefer requested redirect_to or cookie.
 * Never return assets/internal endpoints.
 *
 * NOTE: We do NOT clear the cookie here; /continue clears it after it is consumed.
 */
add_filter('login_redirect', function ($redirect_to, $requested_redirect_to, $user) {

    // Candidate order: requested -> request param -> cookie
    $candidate = $requested_redirect_to ?: ($_REQUEST['redirect_to'] ?? '');
    $path = aspen_sanitize_intended_path($candidate);

    if (!$path) {
        $path = aspen_sanitize_intended_path($_COOKIE[ASPEN_INTENDED_COOKIE] ?? '');
    }

    if ($path) {
        return home_url($path);
    }

    // If WP hands us something weird (like wp logo), fall back.
    $fallback_path = aspen_sanitize_intended_path($redirect_to);
    return $fallback_path ? home_url($fallback_path) : home_url('/');

}, 99999, 3);

/**
 * 4) /continue endpoint:
 * - if logged in: redirect to intended and clear cookie
 * - if not: go to login and then back to /continue (cookie should remain)
 */
add_action('template_redirect', function () {
    if (!is_page('continue')) {
        return;
    }

    // Prefer explicit redirect_to query param if present, else cookie.
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

    // Not logged in: go to login and then back here.
    wp_safe_redirect(wp_login_url(home_url('/continue/')));
    exit;
});

/**
 * 5) Bypass Force Login to allow for exceptions.
 */
function my_forcelogin_bypass($bypass, $visited_url) {
    if (is_page('register') || is_page('continue') || is_page('login')) {
        return true;
    }

    if (!empty($_GET['ff_landing']) || !empty($_GET['entry_confirmation'])) {
        return true;
    }

    return $bypass;
}
add_filter('v_forcelogin_bypass', 'my_forcelogin_bypass', 10, 2);

add_filter('login_url', function ($login_url, $redirect, $force_reauth) {
    return home_url('/login/');
}, 10, 3);

add_shortcode('register_button', function ($atts) {
    $atts = shortcode_atts([
        'text'  => 'Register',
        'class' => 'register-button',
        'url'   => home_url('/register/')
    ], $atts);

    return sprintf(
        '<a href="%s" class="%s">%s</a>',
        esc_url($atts['url']),
        esc_attr($atts['class']),
        esc_html($atts['text'])
    );
});

/**
 * Shortcode: [logout_link]
 * Outputs: Log Out {display_name}
 */
add_shortcode('logout_link', function () {
    if (!is_user_logged_in()) {
        return '';
    }

    $user = wp_get_current_user();

    $logout_url = wp_logout_url(
        add_query_arg([], home_url()) // redirect after logout
    );

    return sprintf(
        '<a href="%s">Logout: %s</a>',
        esc_url($logout_url),
        esc_html($user->display_name)
    );
});
```
