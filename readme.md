# Aspen Intended Login

A WordPress plugin that persists and honors a visitor's intended front-end URL across Force Login, WordPress login, FluentAuth, and FluentForms registration flows.

## What it does

- Stores a short-lived `aspen_intended_path` cookie for logged-out front-end GET requests.
- Keeps redirect destinations on-site and blocks WordPress internals, auth pages, admin AJAX, and common asset/document targets.
- Sends WordPress registration URLs to `/register/` while preserving a safe `redirect_to` value.
- Redirects successful logins to the requested safe destination or stored intended path.
- Provides a `/continue/` helper flow that consumes and clears the intended destination once the user is logged in.
- Bypasses the Force Login plugin for `/register/`, `/continue/`, `/login/`, and FluentForms confirmation flows.
- Adds `[register_button]` and `[logout_link]` shortcodes.

## Installation

1. Copy `aspen-intended-login.php` into `wp-content/plugins/aspen-intended-login/aspen-intended-login.php`.
2. Activate **Aspen Intended Login** in the WordPress admin Plugins screen.
3. Ensure your site has public pages at `/register/`, `/continue/`, and `/login/`.

## Shortcodes

### `[register_button]`

Outputs a registration link.

Optional attributes:

- `text` — link text. Default: `Register`.
- `class` — CSS class. Default: `register-button`.
- `url` — link target. Default: `/register/`.

### `[logout_link]`

Outputs `Logout: {display_name}` for logged-in users and nothing for anonymous visitors.
