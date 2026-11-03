<?php
/**
 * @package     Joomla.Plugin
 * @subpackage  System.googleauth
 *
 * @copyright   Copyright (C) 2026 TommiLin. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

namespace Joomla\Plugin\System\Googleauth\Extension;

defined('_JEXEC') or die;

use Joomla\CMS\Component\ComponentHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Http\HttpFactory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Mail\MailerFactoryInterface;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\CMS\User\UserHelper;
use Joomla\Database\DatabaseAwareTrait;
use Joomla\Event\SubscriberInterface;

class Googleauth extends CMSPlugin implements SubscriberInterface
{
    use DatabaseAwareTrait;

    private const STATE_KEY = 'googleauth.oauth_state';
    private const PENDING_CONSENT_KEY = 'googleauth.pending_consent';
    private const GOOGLE_SUB_PARAM = 'googleauth_sub';
    private const PRIVACY_PARAM = 'google_privacy_accepted';
    private const STATE_TTL = 600;      // 10 minutes
    private const CONSENT_TTL = 900;    // 15 minutes
    private const MAX_AVATAR_BYTES = 3 * 1024 * 1024; // 3 MB
    // Fallback only — the real values live in the plugin's terms_version /
    // privacy_version params so an admin can force re-consent by bumping
    // them, with no code deploy.
    private const DEFAULT_DOC_VERSION = '2026-07-23';

    /** @var bool|null cached result of the Community Builder table check */
    private ?bool $cbAvailable = null;

    public static function getSubscribedEvents(): array
    {
        return [
            'onAfterInitialise' => 'onAfterInitialise',
            'onAfterRender' => 'onAfterRender',
        ];
    }

    public function onAfterInitialise(): void
    {
        $app = $this->getApplication();
        $input = $app->input;

        if (
            $input->getCmd('option') === 'com_ajax'
            && $input->getCmd('plugin') === 'googleauth'
            && $input->getCmd('group') === 'system'
        ) {
            $this->handleGoogleCallback();
        }
    }

    public function onAfterRender(): void
    {
        $app = $this->getApplication();

        if ($app->isClient('administrator')) {
            return;
        }

        $user = $app->getIdentity();
        if ($user && $user->id > 0) {
            return;
        }

        $clientId = trim((string) $this->params->get('client_id'));
        if ($clientId === '') {
            return;
        }

        /*
         * JReviews AJAX requests must not overwrite the OAuth state issued
         * for the Google button on the full HTML page.
         */
        $input = $app->input;
        $isAjaxRequest = $input->getCmd('format') === 'ajax'
            || $input->getCmd('option') === 'com_ajax'
            || strtolower($input->server->getString('HTTP_X_REQUESTED_WITH', '')) === 'xmlhttprequest';

        if ($isAjaxRequest) {
            return;
        }

        $body = $app->getBody();

        /*
         * Keep the original plugin's state lifecycle: create an OAuth state only
         * while rendering an actual login surface. This prevents unrelated
         * background responses from replacing the state stored for a visible button.
         */
        $loginSurfacePattern = '#(?:<form\b[^>]*(?:cbLoginForm|mod-login|login-form|com_comprofiler|jrForm)[^>]*>|<div\b[^>]*(?:jrLoginBox|jrLoginForm|jr-login-form)[^>]*>)#is';

        if (!preg_match($loginSurfacePattern, $body)) {
            return;
        }

        $state = bin2hex(random_bytes(32));
        $this->storeOauthState($state);
        $app->getSession()->set('googleauth.return_url', Uri::getInstance()->toString(['scheme', 'host', 'port', 'path', 'query']));

        /*
         * 'select_account' is always kept so the account chooser still
         * appears. 'consent' additionally forces Google's own permission
         * screen on every login (re-confirming the requested scopes) and can
         * be switched off from the plugin's admin settings, independently of
         * the site's own require_consent (Privacy/Terms) screen.
         */
        $promptValues = ['select_account'];
        if ((bool) $this->params->get('force_google_consent', 1)) {
            $promptValues[] = 'consent';
        }

        $googleUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query([
            'client_id' => $clientId,
            'redirect_uri' => $this->getCallbackUrl(),
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'state' => $state,
            'prompt' => implode(' ', $promptValues),
        ], '', '&', PHP_QUERY_RFC3986);

        $this->loadLanguage();
        $buttonText = Text::_('PLG_SYSTEM_GOOGLEAUTH_LOGIN_BUTTON');

        // Color schemes from Google's Sign in with Google branding guidelines
        // (Supported button modes: Light, Dark, Neutral). The "G" logo keeps its brand colors.
        $buttonThemes = [
            'light'   => ['bg' => '#FFFFFF', 'border' => '1px solid #747775', 'color' => '#1F1F1F'],
            // The look the button had before the guideline schemes: light-gray border and the
            // original hover (the base .google-login-btn:hover rule, no scheme override).
            'classic' => ['bg' => '#FFFFFF', 'border' => '1px solid #dadce0', 'color' => '#3c4043'],
            'dark'    => ['bg' => '#131314', 'border' => '1px solid #8E918F', 'color' => '#E3E3E3'],
            'neutral' => ['bg' => '#F2F2F2', 'border' => '0', 'color' => '#1F1F1F'],
        ];
        $buttonTheme = (string) $this->params->get('button_theme', 'light');
        if (!isset($buttonThemes[$buttonTheme])) {
            $buttonTheme = 'light';
        }
        $themeColors = $buttonThemes[$buttonTheme];

        // Button type / shape (Google's "Supported button modes": standard or icon-only,
        // pill/round or rectangular/square) and the optional "copy the login form's
        // submit button style" mode.
        $isIconOnly = (string) $this->params->get('button_type', 'standard') === 'icon';
        $isPill = (string) $this->params->get('button_shape', 'rectangular') === 'pill';
        $matchSubmit = (bool) $this->params->get('match_submit_style', 0);

        $iconAlignMap = ['left' => 'flex-start', 'center' => 'center', 'right' => 'flex-end'];
        $iconAlign = (string) $this->params->get('icon_align', 'left');
        if (!isset($iconAlignMap[$iconAlign])) {
            $iconAlign = 'left';
        }

        $containerStyle = 'flex-basis:100%;width:100%;margin-top:12px;clear:both;'
            . ($isIconOnly ? 'display:flex;justify-content:' . $iconAlignMap[$iconAlign] . ';' : '');
        $matchIconHeight = (bool) $this->params->get('icon_match_height', 1);
        $containerAttrs = ($matchSubmit ? ' data-match-submit="1"' : '')
            . ($isIconOnly && $matchIconHeight ? ' data-match-height="1"' : '');

        $layoutStyle = 'display:flex;align-items:center;justify-content:center;gap:12px;box-sizing:border-box;text-decoration:none;';

        if ($matchSubmit) {
            // Look and hover come from the CSS classes copied from the submit button by the
            // injected script, so no colors/border/radius/hover rules are applied here.
            $linkClass = 'google-login-btn-match';
            // Icon-only: a 40x40 square without the template's side padding (the script makes it
            // as tall as the submit button when "match icon height" is on).
            $linkStyle = $layoutStyle . ($isIconOnly ? 'width:40px;height:40px;padding:0;' : 'width:100%;');
        } else {
            $linkClass = 'google-login-btn google-login-btn--' . $buttonTheme
                . ' google-login-btn--' . ($isPill ? 'pill' : 'rectangular');
            $linkStyle = $layoutStyle
                . ($isIconOnly ? 'width:40px;height:40px;padding:0;' : 'width:100%;min-height:40px;padding:10px 16px;')
                . 'background:' . $themeColors['bg'] . ';border:' . $themeColors['border'] . ';'
                . 'border-radius:' . ($isPill ? '999px' : '4px') . ';'
                . 'color:' . $themeColors['color'] . ';font:inherit;font-weight:500;line-height:1.4;';
        }

        $buttonLabel = htmlspecialchars($buttonText, ENT_QUOTES, 'UTF-8');

        $buttonHtml = '<div class="google-auth-container"' . $containerAttrs . ' style="' . $containerStyle . '">'
          . '<a href="' . htmlspecialchars($googleUrl, ENT_QUOTES, 'UTF-8') . '" class="' . $linkClass . '" '
             . ($isIconOnly ? 'aria-label="' . $buttonLabel . '" title="' . $buttonLabel . '" ' : '')
             . 'style="' . $linkStyle . '">'
             . '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="18" height="18" aria-hidden="true">'
             . '<path fill="#EA4335" d="M24 9.5c3.54 0 6.72 1.22 9.22 3.61l6.9-6.9C35.9 2.3 30.4 0 24 0 14.64 0 6.56 5.38 2.56 13.22l8.04 6.24C12.53 13.52 17.8 9.5 24 9.5z"/>'
             . '<path fill="#4285F4" d="M46.98 24.55c0-1.57-.14-3.08-.4-4.55H24v9.09h12.94c-.56 2.98-2.24 5.5-4.77 7.18l7.73 6C44.4 38.1 46.98 31.84 46.98 24.55z"/>'
             . '<path fill="#FBBC05" d="M10.6 28.54A14.5 14.5 0 0 1 9.5 24c0-1.58.39-3.08 1.1-4.54l-8.04-6.24A23.95 13.22 0 0 0 0 24c0 3.87.93 7.52 2.56 10.78l8.04-6.24z"/>'
             . '<path fill="#34A853" d="M24 48c6.48 0 11.92-2.14 15.9-5.82l-7.73-6c-2.15 1.45-4.9 2.32-8.17 2.32-6.2 0-11.47-4.02-13.4-9.46l-8.04 6.24C6.56 42.62 14.64 48 24 48z"/>'
             . '</svg>'
             . ($isIconOnly ? '' : '<span>' . $buttonLabel . '</span>')
             . '</a></div>';

        $buttonJson = json_encode(
            $buttonHtml,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
        );

        $injectionScript = <<<'JS'
<script>
(function () {
    'use strict';

    const buttonMarkup = __GOOGLEAUTH_BUTTON_HTML__;
    const jreviewsSelector = '#jr-login-form form, .jrLoginForm form, .jrLoginBox form, form[name="jrLogin"]';
    const standardLoginSelector = [
        'form#login-form',
        'form.cbLoginForm',
        'form.mod-login',
        'form.login-form',
        'form.com_comprofiler',
        'form[name="login"]'
    ].join(',');

    function isJReviewsLoginForm(form) {
        if (form.matches(jreviewsSelector)) {
            return true;
        }

        // JReviews' "Account required" layout has a generic jrForm class.
        // The two hidden fields distinguish its login form from review search.
        return form.classList.contains('jrForm')
            && form.querySelector('input[name="data[controller]"][value="users"]') !== null
            && form.querySelector('input[name="data[action]"][value="login"]') !== null;
    }

    function createButton() {
        const template = document.createElement('template');
        template.innerHTML = buttonMarkup.trim();

        return template.content.firstElementChild;
    }

    function directSiblingButton(form) {
        const next = form.nextElementSibling;

        return next && next.classList.contains('google-auth-container') ? next : null;
    }

    function fitReviewLoginButton(form, button) {
        // Only the compact login form shown while adding a review needs this width.
        // Sidebar and other JReviews login buttons deliberately keep their current layout.
        if (!button || !form.closest('#jr-login-form')) {
            return;
        }

        const formWidth = Math.ceil(form.getBoundingClientRect().width);

        if (formWidth <= 0) {
            return;
        }

        button.style.flexBasis = 'auto';
        button.style.width = formWidth + 'px';
        button.style.maxWidth = '100%';
    }

    function placeJReviewsButton(form) {
        const scope = form.closest('.jrLoginBox, .jrLoginForm, #jr-login-form') || form.parentElement;

        if (!scope) {
            return;
        }

        let button = scope.querySelector('.google-auth-container') || directSiblingButton(form);

        if (!button) {
            button = createButton();
        }

        if (button && button.previousElementSibling !== form) {
            form.insertAdjacentElement('afterend', button);
        }

        fitReviewLoginButton(form, button);
    }

    function placeStandardLoginButton(form) {
        if (isJReviewsLoginForm(form)) {
            return;
        }

        let button = form.querySelector('.google-auth-container') || directSiblingButton(form);

        if (!button) {
            button = createButton();
        }

        if (!button) {
            return;
        }

        const helperLink = form.querySelector(
            'a[href*="lostpassword"], a[href*="register"]'
        );

        if (helperLink) {
            const helperBlock = helperLink.closest(
                'ul, ol, .login-links, .login-helpers, .forgot-password, .form-group, .control-group'
            );

            if (helperBlock && helperBlock !== form && helperBlock.parentNode) {
                if (button.nextElementSibling !== helperBlock) {
                    helperBlock.parentNode.insertBefore(button, helperBlock);
                }
            } else if (button.nextElementSibling !== helperLink) {
                helperLink.insertAdjacentElement('beforebegin', button);
            }

            return;
        }

        const submit = form.querySelector(
            'button[type="submit"], input[type="submit"], button:not([type])'
        );
        const submitBlock = submit && submit.closest(
            '.control-group, .form-group, .login-button, .jrLoginButton, .uk-margin'
        );

        if (submitBlock && submitBlock !== form) {
            if (submitBlock.nextElementSibling !== button) {
                submitBlock.insertAdjacentElement('afterend', button);
            }
        } else if (form.lastElementChild !== button) {
            form.append(button);
        }
    }

    function findSubmit(form) {
        return form.querySelector(
            'button[type="submit"], input[type="submit"], button:not([type])'
        );
    }

    function matchIconHeight(form, container) {
        // Icon-only mode (when enabled): make the icon button a square as tall as the form's own submit button.
        if (!container || container.getAttribute('data-match-height') !== '1') {
            return;
        }

        const link = container.querySelector('a');
        const submit = findSubmit(form);

        if (!link || !submit) {
            return;
        }

        const size = Math.round(submit.getBoundingClientRect().height);

        if (size <= 0) {
            return;
        }

        const px = size + 'px';

        if (link.style.height !== px) {
            link.style.width = px;
            link.style.height = px;
            link.style.minHeight = '0';
            link.style.padding = '0';
        }
    }

    function matchSubmitStyle(form, container) {
        // Optional mode: reuse the login form's own submit button classes so the Google button
        // looks and reacts on hover exactly like the template's button.
        if (!container || container.getAttribute('data-match-submit') !== '1') {
            return;
        }

        const link = container.querySelector('a');

        if (!link || link.getAttribute('data-submit-matched') === '1') {
            return;
        }

        const submit = findSubmit(form);

        if (!submit) {
            return;
        }

        submit.classList.forEach(function (name) {
            if (name.indexOf('webauthn') === -1) {
                link.classList.add(name);
            }
        });

        link.setAttribute('data-submit-matched', '1');
    }

    function matchAllSubmitStyles() {
        document.querySelectorAll('.google-auth-container').forEach(function (container) {
            const sibling = container.previousElementSibling;
            const form = container.closest('form')
                || (sibling && sibling.tagName === 'FORM' ? sibling : null);

            if (!form) {
                return;
            }

            matchSubmitStyle(form, container);
            matchIconHeight(form, container);
        });
    }

    function addGoogleButtons() {
        document.querySelectorAll('form').forEach(function (form) {
            if (isJReviewsLoginForm(form)) {
                placeJReviewsButton(form);
            }
        });

        const handled = new Set(document.querySelectorAll(standardLoginSelector));
        handled.forEach(placeStandardLoginButton);

        // Joomla core login forms whose id/class differ from the fixed selectors above
        // (e.g. YOOtheme/Cassiopeia render id="login-form-16" with no class or name).
        // Every one of them posts task=user.login, so detect by that hidden field.
        document.querySelectorAll('form').forEach(function (form) {
            if (handled.has(form) || isJReviewsLoginForm(form)) {
                return;
            }

            if (form.querySelector('input[name="task"][value="user.login"]') !== null) {
                placeStandardLoginButton(form);
            }
        });

        matchAllSubmitStyles();
    }

    function start() {
        addGoogleButtons();

        // Recalculate when the form becomes visible or the viewport changes.
        window.addEventListener('resize', addGoogleButtons);
        document.addEventListener('click', function () {
            window.setTimeout(addGoogleButtons, 0);
        });

        let scheduled = false;
        const observer = new MutationObserver(function () {
            if (scheduled) {
                return;
            }

            scheduled = true;
            window.setTimeout(function () {
                scheduled = false;
                addGoogleButtons();
            }, 0);
        });

        observer.observe(document.body, { childList: true, subtree: true });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start, { once: true });
    } else {
        start();
    }
})();
</script>
JS;

        $injectionScript = str_replace('__GOOGLEAUTH_BUTTON_HTML__', (string) $buttonJson, $injectionScript);

        $hoverCss = '
<style>
    .google-login-btn {
        transition: box-shadow .2s ease;
    }

    .google-login-btn:hover {
        border-top-color: #dadce0 !important;
        border-right-color: #c6c6c6 !important;
        border-bottom-color: #c6c6c6 !important;
        border-left-color: #c6c6c6 !important;
        text-decoration: none !important;
        box-shadow:
            0 3px 6px -2px rgba(60,64,67,.30),
            2px 2px 3px -2px rgba(60,64,67,.18),
            -2px 2px 3px -2px rgba(60,64,67,.18);
    }

    /* Per-scheme "lift" on hover: same recipe as the base rule (darker side/bottom edges +
       soft 3-layer shadow), tuned per scheme. A faint light glow is added to every scheme so the
       effect stays visible on dark page backgrounds, where a dark shadow cannot be seen. */
    .google-login-btn.google-login-btn--light:hover {
        border-top-color: #747775 !important;
        border-right-color: #5F6160 !important;
        border-bottom-color: #5F6160 !important;
        border-left-color: #5F6160 !important;
        box-shadow:
            0 3px 6px -2px rgba(60,64,67,.30),
            2px 2px 3px -2px rgba(60,64,67,.18),
            -2px 2px 3px -2px rgba(60,64,67,.18),
            0 0 0 1px rgba(255,255,255,.08),
            0 4px 14px -4px rgba(255,255,255,.30);
    }

    .google-login-btn.google-login-btn--dark:hover {
        border-top-color: #8E918F !important;
        border-right-color: #AEB0AF !important;
        border-bottom-color: #AEB0AF !important;
        border-left-color: #AEB0AF !important;
        box-shadow:
            0 3px 6px -2px rgba(0,0,0,.65),
            2px 2px 3px -2px rgba(0,0,0,.45),
            -2px 2px 3px -2px rgba(0,0,0,.45),
            0 0 0 1px rgba(255,255,255,.10),
            0 4px 14px -4px rgba(255,255,255,.32);
    }

    .google-login-btn.google-login-btn--neutral:hover {
        box-shadow:
            0 3px 6px -2px rgba(60,64,67,.40),
            2px 2px 3px -2px rgba(60,64,67,.25),
            -2px 2px 3px -2px rgba(60,64,67,.25),
            0 0 0 1px rgba(255,255,255,.08),
            0 4px 14px -4px rgba(255,255,255,.30);
    }
</style>';

        $body = stripos($body, '</head>') !== false
            ? str_replace('</head>', $hoverCss . '</head>', $body)
            : $hoverCss . $body;

        $body = stripos($body, '</body>') !== false
            ? str_replace('</body>', $injectionScript . '</body>', $body)
            : $body . $injectionScript;

        $app->setBody($body);
    }

    private function handleGoogleCallback(): void
    {
        if ($this->getApplication()->input->getCmd('task') === 'consent') {
            $this->handleConsent();
            return;
        }
        $this->loadLanguage();
        $app = $this->getApplication();
        $input = $app->input;
        $session = $app->getSession();
        $code = $input->getString('code', '');
        $state = $input->getString('state', '');

        if ($code === '' || $state === '' || !$this->consumeOauthState($state)) {
            $this->log('warning', 'oauth_callback', 'Invalid or expired OAuth state');
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_STATE'), 'error');
            return;
        }

        $clientId = trim((string) $this->params->get('client_id'));
        $clientSecret = trim((string) $this->params->get('client_secret'));

        if ($clientId === '' || $clientSecret === '') {
            $this->log('error', 'oauth_callback', 'Missing client_id or client_secret configuration');
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_CONFIG'), 'error');
            return;
        }

        try {
            $http = HttpFactory::getHttp();
            $tokenRequest = http_build_query([
                'code' => $code,
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'redirect_uri' => $this->getCallbackUrl(),
                'grant_type' => 'authorization_code',
            ], '', '&', PHP_QUERY_RFC3986);
            $tokenResponse = $http->post('https://oauth2.googleapis.com/token', $tokenRequest, [
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Accept' => 'application/json',
            ]);
            $tokenData = json_decode($tokenResponse->body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            $this->log('error', 'token_exchange', 'Transport/JSON error: ' . $e->getMessage());
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_CONNECT'), 'error');
            return;
        }

        if (!$this->isSuccessfulResponse($tokenResponse) || empty($tokenData['access_token'])) {
            $this->log(
                'warning',
                'token_exchange',
                'Rejected, HTTP ' . (method_exists($tokenResponse, 'getStatusCode') ? $tokenResponse->getStatusCode() : ($tokenResponse->code ?? 0))
                . ': ' . (string) ($tokenData['error'] ?? 'unknown')
            );
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_TOKEN_REJECTED'), 'error');
            return;
        }

        try {
            $profileResponse = $http->get(
                'https://openidconnect.googleapis.com/v1/userinfo',
                ['Authorization' => 'Bearer ' . $tokenData['access_token'], 'Accept' => 'application/json']
            );
            $profile = json_decode($profileResponse->body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            $this->log('error', 'userinfo_fetch', 'Transport/JSON error: ' . $e->getMessage());
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_PROFILE_FETCH'), 'error');
            return;
        }

        if (!$this->isSuccessfulResponse($profileResponse)) {
            $this->log(
                'warning',
                'userinfo_fetch',
                'Rejected, HTTP ' . (method_exists($profileResponse, 'getStatusCode') ? $profileResponse->getStatusCode() : ($profileResponse->code ?? 0))
            );
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_PROFILE_REJECTED'), 'error');
            return;
        }

        $email = strtolower(trim((string) ($profile['email'] ?? '')));
        $googleId = trim((string) ($profile['sub'] ?? ''));
        $emailVerified = ($profile['email_verified'] ?? false) === true;
        $avatarUrl = trim((string) ($profile['picture'] ?? ($profile['image'] ?? '')));

        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !$emailVerified || $googleId === '') {
            $this->log('warning', 'userinfo_fetch', 'Email unverified or missing sub claim');
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_EMAIL_UNVERIFIED'), 'error');
            return;
        }

        $returnUrl = (string) $session->get('googleauth.return_url', Uri::root());

        try {
            $result = $this->resolveGoogleAccount($email, (string) ($profile['name'] ?? ''), $googleId, $avatarUrl);
        } catch (\Throwable $e) {
            $this->log('error', 'resolve_account', $e->getMessage());
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_PREPARE_USER'), 'error');
            return;
        }

        if ($result === null) {
            $this->log('warning', 'resolve_account', 'Email already linked to a different Google account');
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_EMAIL_LINKED'), 'error');
            return;
        }

        if ($result['type'] === 'existing' && !$result['requiresConsent']) {
            if (!$this->loginUser($result['user'])) {
                $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_LOGIN_DENIED'), 'error');
                return;
            }

            // Consent was already given in a previous session — this is an ordinary
            // repeat login, so refreshing the CB profile/avatar here is fine and matches
            // the original plugin's behaviour. (The "no CB before consent" rule is about
            // the very first Accept, not routine subsequent logins.)
            try {
                $this->syncCommunityBuilderUser((int) $result['user']->id, $avatarUrl);
            } catch (\Throwable $e) {
                $this->log('error', 'cb_sync', 'CB profile sync failed for user #' . $result['user']->id . ': ' . $e->getMessage());
            }

            $this->log('info', 'login', 'User #' . $result['user']->id . ' logged in');
            $this->redirectAfterLogin(Text::_('PLG_SYSTEM_GOOGLEAUTH_MSG_SUCCESS'), $returnUrl, false);
            return;
        }

        if ($result['type'] === 'existing') {
            $this->beginConsent([
                'user_id' => (int) $result['user']->id,
                'google_id' => $googleId,
                'avatar_url' => $avatarUrl,
                'renewal_reason' => $result['renewalReason'],
            ], $returnUrl);
            return;
        }

        // New user: nothing has been created yet. Only their raw profile data travels via session.
        $newUserData = [
            'email' => $email,
            'name' => (string) ($profile['name'] ?? ''),
            'googleId' => $googleId,
            'avatarUrl' => $avatarUrl,
        ];

        if (!$result['requiresConsent']) {
            try {
                $user = $this->createGoogleUser($newUserData);
            } catch (\Throwable $e) {
                $this->log('error', 'create_user', $e->getMessage());
                $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_PREPARE_USER'), 'error');
                return;
            }

            if (!$this->loginUser($user)) {
                $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_LOGIN_DENIED'), 'error');
                return;
            }

            $this->log('info', 'login', 'User #' . $user->id . ' logged in (consent not required)');
            $this->redirectAfterLogin(Text::_('PLG_SYSTEM_GOOGLEAUTH_MSG_SUCCESS'), $returnUrl, true);
            return;
        }

        $this->beginConsent(['user_id' => 0, 'new_user' => $newUserData], $returnUrl);
    }

    /**
     * Look up the Google account without ever creating or modifying a Joomla/CB user.
     *
     * @return array{type:'existing', user: User, requiresConsent: bool, renewalReason: ?string}
     *       | array{type:'new', requiresConsent: bool}
     *       | null   (email already linked to a different Google account)
     */
    private function resolveGoogleAccount(string $email, string $name, string $googleId, string $avatarUrl = ''): ?array
    {
        $user = $this->findUserByGoogleId($googleId);

        if ($user !== null) {
            return $this->describeExistingAccount($user);
        }

        $user = $this->findUserByEmail($email);
        if ($user !== null) {
            $storedGoogleId = (string) $user->getParam(self::GOOGLE_SUB_PARAM, '');
            if ($storedGoogleId !== '' && !hash_equals($storedGoogleId, $googleId)) {
                return null;
            }

            // Existing accounts are linked (Google ID / CB sync written) only after Accept.
            return $this->describeExistingAccount($user);
        }

        return [
            'type' => 'new',
            'requiresConsent' => (bool) $this->params->get('require_consent', 1),
        ];
    }

    /** @return array{type:'existing', user: User, requiresConsent: bool, renewalReason: ?string} */
    private function describeExistingAccount(User $user): array
    {
        $requiresConsent = (bool) $this->params->get('require_consent', 1) && !$this->hasAcceptedTerms($user);

        return [
            'type' => 'existing',
            'user' => $user,
            'requiresConsent' => $requiresConsent,
            // Only meaningful when requiresConsent is true: 'terms', 'privacy',
            // 'both', or null (first-time consent, nothing to compare against).
            // Drives which message the consent screen shows.
            'renewalReason' => $requiresConsent ? $this->getRenewalReason($user) : null,
        ];
    }

    /**
     * @return string|null 'terms' | 'privacy' | 'both' if this is a
     *   re-consent triggered by a version bump, or null for a first-time
     *   consent (nothing accepted yet, so nothing to compare).
     */
    private function getRenewalReason(User $user): ?string
    {
        if (!$this->hasEverAcceptedAnyVersion($user)) {
            return null;
        }

        $record = $this->getConsentRecord($user) ?? [];
        $termsChanged = (string) ($record['terms_version'] ?? '') !== $this->currentTermsVersion();
        $privacyChanged = (string) ($record['privacy_version'] ?? '') !== $this->currentPrivacyVersion();

        return match (true) {
            $termsChanged && $privacyChanged => 'both',
            $termsChanged => 'terms',
            $privacyChanged => 'privacy',
            default => null,
        };
    }

    /**
     * Creates the Joomla user + CB profile for a brand-new Google sign-up.
     * Only ever called from handleConsent() after Accept.
     *
     * @param array{email:string,name:string,googleId:string,avatarUrl:string} $data
     */
    private function createGoogleUser(array $data): User
    {
        $user = new User();
        $user->set('name', $data['name'] !== '' ? $data['name'] : 'Google User');
        $user->set('username', $this->makeUniqueUsername($data['email']));
        $user->set('email', $data['email']);
        $user->set('password', UserHelper::hashPassword(bin2hex(random_bytes(32))));
        $user->set('groups', [$this->getDefaultRegisteredGroupId()]);
        $user->set('block', 0);
        $user->set('activation', '');
        $user->set('registerDate', Factory::getDate()->toSql());
        $user->setParam(self::GOOGLE_SUB_PARAM, $data['googleId']);

        if (!$user->save()) {
            throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_CREATE_FAILED'));
        }

        $this->log('info', 'create_user', 'Created Joomla user #' . $user->id . ' from Google sign-up');

        $user = $this->loadUser((int) $user->id);

        // Optional admin notification (plugin params: notify_admins / admin_notify_ids).
        // Never allowed to break sign-up.
        try {
            $this->notifyAdminsAboutNewUser((int) $user->id);
        } catch (\Throwable $e) {
            $this->log('error', 'notify_admins', 'Admin notification failed for user #' . $user->id . ': ' . $e->getMessage());
        }

        try {
            $this->syncCommunityBuilderUser((int) $user->id, $data['avatarUrl']);
        } catch (\Throwable $e) {
            // CB integration is optional: the account is still created and usable.
            $this->log('error', 'cb_sync', 'CB profile sync failed for user #' . $user->id . ': ' . $e->getMessage());
        }

        return $user;
    }

    /**
     * Emails the configured administrators that a new user registered via Google.
     * Does nothing unless "notify_admins" is enabled and at least one valid admin
     * ID (admin_notify_ids, comma/space separated Joomla user IDs) resolves to an
     * active user with an e-mail address.
     */
    private function notifyAdminsAboutNewUser(int $newUserId): void
    {
        if (!(bool) $this->params->get('notify_admins', 0)) {
            return;
        }

        $rawIds = (string) $this->params->get('admin_notify_ids', '');
        $ids = array_unique(array_filter(
            array_map('intval', preg_split('/[\s,;]+/', $rawIds, -1, PREG_SPLIT_NO_EMPTY) ?: []),
            static fn (int $id): bool => $id > 0 && $id !== $newUserId
        ));

        if ($ids === []) {
            $this->log('warning', 'notify_admins', 'Notification enabled but no valid admin IDs are configured');
            return;
        }

        $this->loadLanguage();
        $siteName = (string) $this->getApplication()->get('sitename', '');
        $subject = Text::sprintf('PLG_SYSTEM_GOOGLEAUTH_NOTIFY_ADMIN_SUBJECT', $siteName);
        $body = Text::sprintf('PLG_SYSTEM_GOOGLEAUTH_NOTIFY_ADMIN_BODY', $siteName, $newUserId);

        foreach ($ids as $adminId) {
            $admin = $this->loadUser($adminId);

            if ((int) $admin->id !== $adminId || (int) $admin->block === 1 || !filter_var($admin->email, FILTER_VALIDATE_EMAIL)) {
                $this->log('warning', 'notify_admins', 'Skipped admin ID ' . $adminId . ' (not found, blocked or no valid e-mail)');
                continue;
            }

            try {
                try {
                    $mailer = Factory::getContainer()->get(MailerFactoryInterface::class)->createMailer();
                } catch (\Throwable $e) {
                    $mailer = Factory::getMailer();
                }

                $mailer->addRecipient($admin->email, $admin->name);
                $mailer->setSubject($subject);
                $mailer->setBody($body);
                $mailer->isHtml(false);

                if ($mailer->Send() === true) {
                    $this->log('info', 'notify_admins', 'Notified admin #' . $adminId . ' about new user #' . $newUserId);
                } else {
                    $this->log('error', 'notify_admins', 'Mail to admin #' . $adminId . ' was not sent');
                }
            } catch (\Throwable $e) {
                $this->log('error', 'notify_admins', 'Mail to admin #' . $adminId . ' failed: ' . $e->getMessage());
            }
        }
    }

    private function getDefaultRegisteredGroupId(): int
    {
        $configured = (int) $this->params->get('default_group', 0);
        if ($configured > 0) {
            return $configured;
        }

        // Fall back to Joomla's standard "Registered" group instead of hardcoding an id.
        $db = $this->getDatabase();
        $query = $db->getQuery(true)
            ->select($db->quoteName('id'))
            ->from($db->quoteName('#__usergroups'))
            ->where($db->quoteName('title') . ' = ' . $db->quote('Registered'));
        $id = (int) $db->setQuery($query)->loadResult();

        return $id > 0 ? $id : 2;
    }

    /**
     * @param array{user_id:int, google_id?:string, new_user?:array, renewal_reason?:?string} $subject
     */
    private function beginConsent(array $subject, string $returnUrl = ''): void
    {
        $token = bin2hex(random_bytes(32));
        $pending = [
            'user_id' => $subject['user_id'],
            'google_id' => $subject['google_id'] ?? '',
            'avatar_url' => $subject['avatar_url'] ?? '',
            'new_user' => $subject['new_user'] ?? null,
            'renewal_reason' => $subject['renewal_reason'] ?? null,
            'token' => $token,
            'created_at' => time(),
            'return_url' => $returnUrl !== '' ? $returnUrl : Uri::root(),
        ];
        $this->getApplication()->getSession()->set(self::PENDING_CONSENT_KEY, $pending);
        $this->getApplication()->redirect($this->getCallbackUrl() . '&task=consent');
    }

    private function handleConsent(): void
    {
        $this->loadLanguage();
        $app = $this->getApplication();
        $session = $app->getSession();
        $pending = $session->get(self::PENDING_CONSENT_KEY, []);

        if ($app->input->getCmd('cancel') === '1') {
            $returnUrl = (string) ($pending['return_url'] ?? Uri::root());
            $session->clear(self::PENDING_CONSENT_KEY);
            $this->getApplication()->redirect($returnUrl);
            return;
        }

        $userId = (int) ($pending['user_id'] ?? -1);
        $token = (string) ($pending['token'] ?? '');
        $createdAt = (int) ($pending['created_at'] ?? 0);
        $newUserData = $pending['new_user'] ?? null;
        $returnUrl = (string) ($pending['return_url'] ?? Uri::root());

        $isExistingUser = $userId > 0 && (string) ($pending['google_id'] ?? '') !== '';
        $isNewUser = $userId === 0 && is_array($newUserData);
        $renewalReason = $pending['renewal_reason'] ?? null;

        if ($token === '' || (!$isExistingUser && !$isNewUser)) {
            $session->clear(self::PENDING_CONSENT_KEY);
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_SESSION_EXPIRED'), 'warning');
            return;
        }

        if ($createdAt <= 0 || (time() - $createdAt) > self::CONSENT_TTL) {
            $session->clear(self::PENDING_CONSENT_KEY);
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_CONSENT_EXPIRED'), 'warning');
            return;
        }

        if (strtoupper($app->input->getMethod()) !== 'POST') {
            $this->renderConsentPage($token, '', $returnUrl, $renewalReason);
            return;
        }

        $submittedToken = $app->input->post->getString('consent_token', '');
        $accepted = $app->input->post->getInt('accept_terms') === 1;

        if (!hash_equals($token, $submittedToken)) {
            // Someone is replaying/forging the form — treat as expired rather than re-rendering.
            $session->clear(self::PENDING_CONSENT_KEY);
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_CONSENT_EXPIRED'), 'warning');
            return;
        }

        if (!$accepted) {
            $this->renderConsentPage($token, Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_CONSENT_REQUIRED'), $returnUrl, $renewalReason);
            return;
        }

        $consentParam = json_encode([
            'accepted_terms' => true,
            'accepted_at' => gmdate('c'),
            'terms_version' => $this->currentTermsVersion(),
            'privacy_version' => $this->currentPrivacyVersion(),
        ], JSON_THROW_ON_ERROR);

        try {
            if ($isNewUser) {
                /** @var array{email:string,name:string,googleId:string,avatarUrl:string} $newUserData */
                $user = $this->createGoogleUser($newUserData);
                $user->setParam(self::PRIVACY_PARAM, $consentParam);
                if (!$user->save()) {
                    $this->log('error', 'consent', 'User::save() failed for new user #' . $user->id . ': ' . $user->getError());
                    throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_SAVE_CONSENT'));
                }
                $user = $this->loadUser((int) $user->id);
            } else {
                $googleId = (string) $pending['google_id'];
                $user = $this->loadUser($userId);
                if ($user->id !== $userId) {
                    throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_USER_NOT_FOUND'));
                }
                $storedGoogleId = (string) $user->getParam(self::GOOGLE_SUB_PARAM, '');
                if ($storedGoogleId !== '' && !hash_equals($storedGoogleId, $googleId)) {
                    throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_ACCOUNT_MISMATCH'));
                }

                $user->setParam(self::GOOGLE_SUB_PARAM, $googleId);
                $user->setParam(self::PRIVACY_PARAM, $consentParam);

                if (!$user->save()) {
                    // Most commonly hit by Super User accounts: Joomla's User::save()
                    // refuses to modify ANY field of a Super User account unless the
                    // *acting* identity (Factory::getUser()) is itself a Super User —
                    // and nobody is logged in yet at this point in the flow. Rather than
                    // fake the acting identity (which would affect ACL checks for
                    // anything else that happens to run mid-request), fall back to a
                    // narrow, params-only update instead. See saveGoogleAuthData() for
                    // the full rationale and its own independent safety checks.
                    $this->log(
                        'info',
                        'consent',
                        'User::save() failed for user #' . $userId . ' (' . $user->getError() . '); falling back to saveGoogleAuthData()'
                    );

                    $this->saveGoogleAuthData($userId, $googleId, $consentParam);
                    // $user already holds the correct params in memory (set above) —
                    // the fallback only needed to actually persist them, since save()
                    // didn't. No reload needed.
                }

                try {
                    $this->syncCommunityBuilderUser((int) $user->id, (string) ($pending['avatar_url'] ?? ''));
                } catch (\Throwable $e) {
                    // CB integration is optional — do not block login on it.
                    $this->log('error', 'cb_sync', 'CB profile sync failed for user #' . $user->id . ': ' . $e->getMessage());
                }
            }
        } catch (\Throwable $e) {
            $this->log('error', 'consent', $e->getMessage());
            $session->clear(self::PENDING_CONSENT_KEY);
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_SAVE_CONSENT_FAIL'), 'error');
            return;
        }

        $session->clear(self::PENDING_CONSENT_KEY);

        if (!$this->loginUser($user)) {
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_LOGIN_DENIED'), 'error');
            return;
        }

        $this->log('info', 'login', 'User #' . $user->id . ' logged in after consent');
        $this->redirectAfterLogin(Text::_('PLG_SYSTEM_GOOGLEAUTH_MSG_CONSENT_SAVED'), $returnUrl, $isNewUser);
    }

    /**
     * Persists this plugin's two params (googleauth_sub, google_privacy_accepted) for an
     * EXISTING Joomla user via a narrow, direct UPDATE of #__users.params — bypassing
     * User::save() entirely.
     *
     * Why this exists: Joomla's User::save() refuses to modify ANY field — including a
     * completely harmless params key — on a Super Users account unless the *acting*
     * identity (Factory::getUser()) is itself a Super User (confirmed by Joomla's own
     * docs: changing even just a Super User's language preference "will fail ... if
     * you're not logged on as a Super User"). Nobody is logged in yet at this point in
     * the OAuth flow, so save() is silently rejected for admin accounts. This method is
     * only ever reached from handleConsent() as a fallback AFTER a normal
     * $user->save() attempt has already failed — ordinary accounts never touch it.
     *
     * Safety invariants, all enforced here independently of whatever the caller did:
     *  - Only the `params` column is ever written. username/email/password/groups/
     *    block/registerDate and everything else are untouched — this cannot be used to
     *    gain any Joomla privilege, since ACL is derived entirely from group
     *    membership, never from params.
     *  - Every existing key already in the user's params JSON is preserved as-is; only
     *    this plugin's own two keys are added/overwritten. Other extensions'/Joomla's
     *    own settings (editor, timezone, 2FA config, ...) travel through unchanged.
     *  - The Google-ID conflict check is re-verified here against the value actually
     *    stored in the database at write time — not whatever the caller's in-memory
     *    User object holds (which may already carry the new, not-yet-persisted value)
     *    — so this method stays safe even if called from somewhere else in the future.
     *  - Corrupt existing JSON is never silently discarded; it's treated as a hard
     *    failure and logged rather than risking data loss.
     *
     * @throws \RuntimeException on a missing user, a corrupt existing params blob, or
     *                           a conflicting Google account (see class docblock rules).
     */
    private function saveGoogleAuthData(int $userId, string $googleId, string $consentParam): void
    {
        if ($userId <= 0) {
            throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_USER_NOT_FOUND'));
        }

        if ($googleId === '') {
            throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_ACCOUNT_MISMATCH'));
        }

        $db = $this->getDatabase();

        // Read the row directly and fresh — never trust an in-memory User object here,
        // since the caller may already have set the new googleauth_sub locally (not
        // yet persisted) on its own copy before falling back to this method.
        $query = $db->getQuery(true)
            ->select($db->quoteName('id') . ', ' . $db->quoteName('params'))
            ->from($db->quoteName('#__users'))
            ->where($db->quoteName('id') . ' = ' . (int) $userId);
        $row = $db->setQuery($query)->loadObject();

        if ($row === null) {
            throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_USER_NOT_FOUND'));
        }

        $rawParams = (string) ($row->params ?? '');
        $params = [];

        if ($rawParams !== '') {
            $decoded = json_decode($rawParams, true);

            if (!is_array($decoded)) {
                $this->log(
                    'error',
                    'save_google_auth_data',
                    'Existing params JSON for user #' . $userId . ' is corrupt; refusing to touch it'
                );
                throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_SAVE_CONSENT'));
            }

            $params = $decoded;
        }

        $storedGoogleId = (string) ($params[self::GOOGLE_SUB_PARAM] ?? '');

        if ($storedGoogleId !== '' && !hash_equals($storedGoogleId, $googleId)) {
            throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_ACCOUNT_MISMATCH'));
        }

        // Only ever touch this plugin's own two keys — every other key (editor,
        // timezone, other extensions' settings, ...) passes through unchanged.
        $params[self::GOOGLE_SUB_PARAM] = $googleId;
        $params[self::PRIVACY_PARAM] = $consentParam;

        $newParamsJson = json_encode($params, JSON_THROW_ON_ERROR);

        $query = $db->getQuery(true)
            ->update($db->quoteName('#__users'))
            ->set($db->quoteName('params') . ' = ' . $db->quote($newParamsJson))
            ->where($db->quoteName('id') . ' = ' . (int) $userId);

        $db->setQuery($query)->execute();

        $this->log(
            'info',
            'save_google_auth_data',
            'Updated googleauth params for user #' . $userId . ' via direct UPDATE (User::save() fallback)'
        );
    }

    private function renderConsentPage(string $token, string $error = '', string $returnUrl = '', ?string $renewalReason = null): void
{
    $this->loadLanguage();
    $message = $error === '' ? '' : '<p class="googleauth-error" role="alert">' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . '</p>';
    $cancelUrl = $this->getCallbackUrl() . '&task=consent&cancel=1';

    $titleKey = match ($renewalReason) {
        'terms' => 'PLG_SYSTEM_GOOGLEAUTH_RENEWAL_TERMS_TITLE',
        'privacy' => 'PLG_SYSTEM_GOOGLEAUTH_RENEWAL_PRIVACY_TITLE',
        'both' => 'PLG_SYSTEM_GOOGLEAUTH_RENEWAL_BOTH_TITLE',
        default => 'PLG_SYSTEM_GOOGLEAUTH_TITLE',
    };
    $descriptionKey = match ($renewalReason) {
        'terms' => 'PLG_SYSTEM_GOOGLEAUTH_RENEWAL_TERMS_DESCRIPTION',
        'privacy' => 'PLG_SYSTEM_GOOGLEAUTH_RENEWAL_PRIVACY_DESCRIPTION',
        'both' => 'PLG_SYSTEM_GOOGLEAUTH_RENEWAL_BOTH_DESCRIPTION',
        default => 'PLG_SYSTEM_GOOGLEAUTH_DESCRIPTION',
    };
    
    $privacyUrl = $this->getConfiguredUrl('privacy_link');
    $termsUrl = $this->getConfiguredUrl('terms_link');
    
    $privacyLabel = Text::_('PLG_SYSTEM_GOOGLEAUTH_PRIVACY_LABEL');
    $termsLabel = Text::_('PLG_SYSTEM_GOOGLEAUTH_TERMS_LABEL');
    
    $privacyLink = $privacyUrl !== ''
        ? '<a href="' . htmlspecialchars($privacyUrl, ENT_QUOTES, 'UTF-8') . '" target="_blank" rel="noopener noreferrer">' . $privacyLabel . '</a>'
        : $privacyLabel;
        
    $termsLink = $termsUrl !== ''
        ? '<a href="' . htmlspecialchars($termsUrl, ENT_QUOTES, 'UTF-8') . '" target="_blank" rel="noopener noreferrer">' . $termsLabel . '</a>'
        : $termsLabel;
        
    $checkboxText = match ($renewalReason) {
        'privacy' => sprintf(Text::_('PLG_SYSTEM_GOOGLEAUTH_TERMS_CHECKBOX_PRIVACY_ONLY'), $privacyLink),
        'terms' => sprintf(Text::_('PLG_SYSTEM_GOOGLEAUTH_TERMS_CHECKBOX_TERMS_ONLY'), $termsLink),
        default => sprintf(Text::_('PLG_SYSTEM_GOOGLEAUTH_TERMS_CHECKBOX'), $privacyLink, $termsLink),
    };

$html = '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    . '<title>' . Text::_($titleKey) . '</title><style>'
    . ':root{color-scheme:light}'
    . '.googleauth-overlay{position:fixed;inset:0;display:grid;place-items:center;padding:20px;background:rgba(15,23,42,.58);font-family:Arial,sans-serif}'
    . '.googleauth-modal{position:relative;width:min(100%,500px);padding:32px;border-radius:18px;background:#fff;box-shadow:0 24px 70px rgba(15,23,42,.3);color:#172033}'
    . '.googleauth-close{position:absolute;top:14px;right:14px;width:36px;height:36px;display:flex;align-items:center;justify-content:center;border-radius:50%;color:#64748b;text-decoration:none;transition:all .2s ease}'
    . '.googleauth-close:hover{background:#f1f5f9;color:#0f172a}'
    . '.googleauth-close svg{width:20px;height:20px;fill:currentColor}'
    . '.googleauth-icon{display:grid;place-items:center;width:48px;height:48px;margin-bottom:18px;border-radius:50%;background:#e8f0fe;color:#4285f4;font-size:25px;font-weight:700}'
    . '.googleauth-modal h1{margin:0 0 12px;font-size:24px;line-height:1.25}'
    . '.googleauth-modal p{margin:0 0 22px;color:#5a6475;line-height:1.55}'
    . '.googleauth-check{display:flex;gap:11px;align-items:flex-start;padding:14px;border:1px solid #dbe2ee;border-radius:10px;background:#f8fafc;color:#334155;font-size:14px;line-height:1.5;cursor:pointer}'
    . '.googleauth-check input{width:18px;height:18px;margin:2px 0 0;accent-color:#4285f4;flex:none}'
    . '.googleauth-check a{color:#2563eb;text-decoration:none}'
    . '.googleauth-check a:hover{text-decoration:underline}'
    . '.googleauth-submit{width:100%;margin-top:20px;padding:12px 18px;border:0;border-radius:9px;background:#4285f4;color:#fff;font-weight:700;font-size:15px;cursor:pointer}'
    . '.googleauth-submit:hover{background:#3374df}'
    . '.googleauth-error{padding:10px 12px;border-radius:8px;background:#fff1f2!important;color:#be123c!important;font-size:14px}'
    . '@media(max-width:480px){.googleauth-modal{padding:24px;border-radius:14px}.googleauth-close{top:10px;right:10px}}'
    . '</style></head><body>'
    . '<div class="googleauth-overlay" role="dialog" aria-modal="true" aria-labelledby="googleauth-title">'
    . '<main class="googleauth-modal">'
    . '<a href="' . htmlspecialchars($cancelUrl, ENT_QUOTES, 'UTF-8') . '" class="googleauth-close" aria-label="' . Text::_('JCLOSE') . '">'
    . '<svg viewBox="0 0 24 24" aria-hidden="true">'
    . '<path d="M18.3 5.71a1 1 0 0 0-1.41 0L12 10.59 7.11 5.7A1 1 0 0 0 5.7 7.11L10.59 12l-4.9 4.89a1 1 0 1 0 1.42 1.41L12 13.41l4.89 4.89a1 1 0 0 0 1.41-1.41L13.41 12l4.89-4.89a1 1 0 0 0 0-1.4z"/>'
    . '</svg>'
    . '</a>'
    . '<h1 id="googleauth-title">' . Text::_($titleKey) . '</h1>'
    . '<p>' . Text::_($descriptionKey) . '</p>'
    . $message
    . '<form method="post" action="' . htmlspecialchars($this->getCallbackUrl() . '&task=consent', ENT_QUOTES, 'UTF-8') . '">'
    . '<input type="hidden" name="consent_token" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">'
    . '<label class="googleauth-check">'
    . '<input type="checkbox" name="accept_terms" value="1" required>'
    . '<span>' . $checkboxText . '</span>'
    . '</label>'
    . '<button class="googleauth-submit" type="submit">'
    . Text::_('PLG_SYSTEM_GOOGLEAUTH_SUBMIT_BUTTON')
    . '</button>'
    . '</form>'
    . '</main>'
    . '</div>'
    . '</body></html>';

echo $html;
$this->getApplication()->close();
    }

    /**
     * NOTE: Joomla's own $app->login() only works through password-based authentication
     * plugins, so it cannot be used for an already-verified Google identity. This mirrors
     * what other Joomla social-login extensions do: fork the session, load the identity,
     * and then fire the standard 'onUserAfterLogin' event so ACL caches, audit/logging
     * plugins, and anything else listening for a login still run as they would for a
     * normal login. We deliberately do NOT force `com_users.mfa_checked = 0` any more,
     * since that silently bypasses any MFA method the account may already have configured
     * — if the site requires MFA for this account, the standard com_users MFA challenge
     * should still trigger on the next privileged action instead of being skipped here.
     */
    private function loginUser(User $user): bool
    {
        $app = $this->getApplication();
        $session = $app->getSession();

        if ($user->id <= 0 || (int) $user->block === 1 || !$user->authorise('core.login.site')) {
            return false;
        }

        if (method_exists($session, 'fork')) {
            $session->fork();
        } elseif (method_exists($session, 'regenerate')) {
            $session->regenerate(true);
        }

        $user->guest = 0;
        $session->set('user', $user);
        $app->loadIdentity($user);

        if ($app->get('session_metadata', true)) {
            $app->checkSession();
        }

        $user->setLastVisit();

        try {
            \Joomla\CMS\Plugin\PluginHelper::importPlugin('user');
            $app->triggerEvent('onUserAfterLogin', [[
                'user' => $user,
                'responseType' => 'GoogleAuth',
            ]]);
        } catch (\Throwable $e) {
            $this->log('warning', 'login', 'onUserAfterLogin listeners failed: ' . $e->getMessage());
        }

        return true;
    }

    private function currentTermsVersion(): string
    {
        $v = trim((string) $this->params->get('terms_version', ''));
        return $v !== '' ? $v : self::DEFAULT_DOC_VERSION;
    }

    private function currentPrivacyVersion(): string
    {
        $v = trim((string) $this->params->get('privacy_version', ''));
        return $v !== '' ? $v : self::DEFAULT_DOC_VERSION;
    }

    /** @return array{accepted_terms?:bool,accepted_at?:string,terms_version?:string,privacy_version?:string}|null */
    private function getConsentRecord(User $user): ?array
    {
        $value = $user->getParam(self::PRIVACY_PARAM, '');
        $params = is_string($value) && $value !== '' ? json_decode($value, true) : null;
        return is_array($params) ? $params : null;
    }

    /**
     * True only if the user accepted the CURRENT terms_version and
     * privacy_version. An old acceptance on a now-superseded version does
     * not count — this is what actually triggers re-consent.
     */
    private function hasAcceptedTerms(User $user): bool
    {
        $record = $this->getConsentRecord($user);

        if ($record === null || empty($record['accepted_terms'])) {
            return false;
        }

        return (string) ($record['terms_version'] ?? '') === $this->currentTermsVersion()
            && (string) ($record['privacy_version'] ?? '') === $this->currentPrivacyVersion();
    }

    /**
     * True if the user has EVER accepted any version. Used only to tell
     * "first-time consent" apart from "re-consent because the policy
     * changed" for the wording shown on the consent screen — it plays no
     * part in the actual access-control decision (hasAcceptedTerms() above
     * is what gates that).
     */
    private function hasEverAcceptedAnyVersion(User $user): bool
    {
        $record = $this->getConsentRecord($user);

        return $record !== null && !empty($record['accepted_terms']);
    }

    private function findUserByGoogleId(string $googleId): ?User
    {
        $db = $this->getDatabase();
        $query = $db->getQuery(true)
            ->select($db->quoteName('id'))
            ->from($db->quoteName('#__users'))
            ->where($db->quoteName('params') . ' LIKE ' . $db->quote('%"' . self::GOOGLE_SUB_PARAM . '":"' . $googleId . '"%'));
        $userId = (int) $db->setQuery($query)->loadResult();
        return $userId > 0 ? $this->loadUser($userId) : null;
    }

    private function findUserByEmail(string $email): ?User
    {
        $db = $this->getDatabase();
        $query = $db->getQuery(true)
            ->select($db->quoteName('id'))
            ->from($db->quoteName('#__users'))
            ->where($db->quoteName('email') . ' = ' . $db->quote($email));
        $userId = (int) $db->setQuery($query)->loadResult();
        return $userId > 0 ? $this->loadUser($userId) : null;
    }

    private function makeUniqueUsername(string $email): string
    {
        $base = strstr($email, '@', true) ?: 'googleuser';
        $base = preg_replace('/[^a-zA-Z0-9._-]/', '', $base) ?: 'googleuser';
        $base = substr($base, 0, 80);
        $username = $base;
        $counter = 1;

        while ($this->usernameExists($username)) {
            $suffix = '-' . $counter++;
            $username = substr($base, 0, 80 - strlen($suffix)) . $suffix;
        }

        return $username;
    }

    private function isSuccessfulResponse(object $response): bool
    {
        $statusCode = method_exists($response, 'getStatusCode')
            ? $response->getStatusCode()
            : ($response->code ?? 0);

        return $statusCode >= 200 && $statusCode < 300;
    }

    private function getConfiguredUrl(string $parameter): string
    {
        $url = trim((string) $this->params->get($parameter, ''));
        return filter_var($url, FILTER_VALIDATE_URL) && preg_match('#^https?://#i', $url) ? $url : '';
    }

    private function isCommunityBuilderAvailable(): bool
    {
        if ($this->cbAvailable !== null) {
            return $this->cbAvailable;
        }

        $db = $this->getDatabase();
        $cbTable = $db->getPrefix() . 'comprofiler';

        return $this->cbAvailable = in_array($cbTable, $db->getTableList(), true);
    }

    private function syncCommunityBuilderUser(int $userId, string $avatarUrl = ''): void
    {
        if (!$this->isCommunityBuilderAvailable()) {
            return;
        }

        $db = $this->getDatabase();

        $joomlaUser = $this->loadUser($userId);
        $nameParts = explode(' ', trim($joomlaUser->name), 2);
        $firstName = $nameParts[0] ?? $joomlaUser->username;
        $lastName = $nameParts[1] ?? '';

        // Проверяем, существует ли уже запись в CB
        $query = $db->getQuery(true)
            ->select($db->quoteName('id') . ', ' . $db->quoteName('avatar'))
            ->from($db->quoteName('#__comprofiler'))
            ->where($db->quoteName('id') . ' = ' . (int) $userId);

        $db->setQuery($query);
        $cbUser = $db->loadObject();
        $exists = $cbUser !== null;

        $avatarFileName = '';

        // Google's avatar is only ever applied when the CB profile doesn't exist yet.
        // Once created, the user's avatar (whatever they set it to, including "none") is theirs —
        // subsequent logins must never overwrite it, even if it's currently empty.
        if ($avatarUrl !== '' && !$exists) {
            $avatarFileName = $this->downloadCommunityBuilderAvatar($userId, $avatarUrl);
        }

        if ($exists) {
            $query = $db->getQuery(true)
                ->update($db->quoteName('#__comprofiler'))
                ->set($db->quoteName('confirmed') . ' = 1')
                ->set($db->quoteName('approved') . ' = 1')
                ->set($db->quoteName('firstname') . ' = ' . $db->quote($firstName))
                ->set($db->quoteName('lastname') . ' = ' . $db->quote($lastName));

            if ($avatarFileName !== '') {
                $query->set($db->quoteName('avatar') . ' = ' . $db->quote($avatarFileName))
                      ->set($db->quoteName('avatarapproved') . ' = 1');
            }

            $query->where($db->quoteName('id') . ' = ' . (int) $userId);
        } else {
            $columns = [
                $db->quoteName('id'),
                $db->quoteName('user_id'),
                $db->quoteName('confirmed'),
                $db->quoteName('approved'),
                $db->quoteName('firstname'),
                $db->quoteName('lastname')
            ];

            $values = [
                (int) $userId,
                (int) $userId,
                1,
                1,
                $db->quote($firstName),
                $db->quote($lastName)
            ];

            if ($avatarFileName !== '') {
                $columns[] = $db->quoteName('avatar');
                $columns[] = $db->quoteName('avatarapproved');
                $values[] = $db->quote($avatarFileName);
                $values[] = 1;
            }

            $query = $db->getQuery(true)
                ->insert($db->quoteName('#__comprofiler'))
                ->columns($columns)
                ->values(implode(', ', $values));
        }

        $db->setQuery($query);
        $db->execute();
    }

    /**
     * Fetches raw avatar bytes, trying Joomla's HTTP client first and falling back to a
     * redirect-following request if that fails — Google's avatar URLs (googleusercontent.com)
     * commonly 30x-redirect, which Joomla's default HTTP client does not always follow.
     * Unlike the original plugin's fallback, TLS certificate verification is never disabled.
     */
    private function fetchAvatarBytes(string $avatarUrl): string
    {
        try {
            $response = HttpFactory::getHttp()->get($avatarUrl);
            if ($this->isSuccessfulResponse($response) && !empty($response->body)) {
                return $response->body;
            }
            $this->log('info', 'avatar_download', 'Primary HTTP client returned no usable body, trying fallback');
        } catch (\Throwable $e) {
            $this->log('info', 'avatar_download', 'Primary HTTP client failed (' . $e->getMessage() . '), trying fallback');
        }

        if (function_exists('curl_init')) {
            $ch = curl_init($avatarUrl);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_TIMEOUT => 10,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);
            $body = curl_exec($ch);
            $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            curl_close($ch);

            if ($body !== false && $httpCode >= 200 && $httpCode < 300 && $body !== '') {
                return $body;
            }

            $this->log('warning', 'avatar_download', 'curl fallback failed: HTTP ' . $httpCode . ($error !== '' ? ', ' . $error : ''));
        } else {
            $ctx = stream_context_create([
                'http' => ['method' => 'GET', 'timeout' => 10, 'follow_location' => 1],
                // Certificate verification stays ON — this is not the insecure fallback the
                // original plugin used.
                'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
            ]);

            $body = file_get_contents($avatarUrl, false, $ctx);
            if ($body !== false && $body !== '') {
                return $body;
            }

            $this->log('warning', 'avatar_download', 'stream_context fallback returned no data');
        }

        return '';
    }

    /**
     * Downloads the Google avatar, enforces a size cap, and confirms the payload is really
     * an image before writing it to disk. Returns the generated filename, or '' if anything
     * about the download was rejected.
     */
    private function downloadCommunityBuilderAvatar(int $userId, string $avatarUrl): string
    {
        $imageContent = $this->fetchAvatarBytes($avatarUrl);

        if ($imageContent === '') {
            return '';
        }

        if (strlen($imageContent) > self::MAX_AVATAR_BYTES) {
            $this->log('warning', 'avatar_download', 'Avatar exceeds size limit');
            return '';
        }

        $imageInfo = @getimagesizefromstring($imageContent);
        $allowedMimes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];

        if ($imageInfo === false || !in_array($imageInfo['mime'] ?? '', $allowedMimes, true)) {
            $this->log('warning', 'avatar_download', 'Rejected: content is not a recognised image type');
            return '';
        }

        $mime = $imageInfo['mime'];
        $extension = match ($mime) {
            'image/png' => 'png',
            'image/webp' => 'webp',
            'image/gif' => 'gif',
            default => 'jpg',
        };

        $uploadDir = JPATH_ROOT . '/images/comprofiler/';

        if (!is_dir($uploadDir) && !mkdir($uploadDir, 0755, true) && !is_dir($uploadDir)) {
            $this->log('error', 'avatar_download', 'Failed to create upload directory: ' . $uploadDir);
            return '';
        }

        if (!is_writable($uploadDir)) {
            $this->log('error', 'avatar_download', 'Upload directory is not writable: ' . $uploadDir);
            return '';
        }

        if (extension_loaded('gd')) {
            // Normalise everything to JPEG so the stored file extension always matches its content.
            $jpegContent = $this->convertImageToJpeg($imageContent, $mime);

            if ($jpegContent !== null) {
                $avatarFileName = $userId . '_' . substr(md5(uniqid('', true)), 0, 13) . '.jpg';
                $destination = $uploadDir . $avatarFileName;

                if (file_put_contents($destination, $jpegContent) === false) {
                    $this->log('error', 'avatar_download', 'Failed to write avatar file: ' . $destination);
                    return '';
                }

                $thumbnail = $this->makeThumbnail($jpegContent, 100, 100);
                if ($thumbnail === null || file_put_contents($uploadDir . 'tn' . $avatarFileName, $thumbnail) === false) {
                    $this->log('warning', 'avatar_download', 'Failed to write avatar thumbnail: ' . $destination);
                }

                return $avatarFileName;
            }

            $this->log('warning', 'avatar_download', 'GD conversion failed, falling back to storing original bytes');
        } else {
            $this->log('info', 'avatar_download', 'GD extension not available, storing original image bytes as-is');
        }

        // GD unavailable (or conversion failed): still store the file, using its real
        // extension, rather than dropping the avatar entirely. It has already passed the
        // size cap and a genuine getimagesizefromstring() check above, so this is safe —
        // just not re-encoded/resized.
        $avatarFileName = $userId . '_' . substr(md5(uniqid('', true)), 0, 13) . '.' . $extension;
        $destination = $uploadDir . $avatarFileName;

        if (file_put_contents($destination, $imageContent) === false) {
            $this->log('error', 'avatar_download', 'Failed to write avatar file: ' . $destination);
            return '';
        }

        if (copy($destination, $uploadDir . 'tn' . $avatarFileName) === false) {
            $this->log('warning', 'avatar_download', 'Failed to write avatar thumbnail copy: ' . $destination);
        }

        return $avatarFileName;
    }

    private function convertImageToJpeg(string $imageContent, string $mime): ?string
    {
        $source = @imagecreatefromstring($imageContent);
        if ($source === false) {
            return null;
        }

        // Flatten transparency (PNG/WebP/GIF) onto white before JPEG export.
        $width = imagesx($source);
        $height = imagesy($source);
        $flattened = imagecreatetruecolor($width, $height);
        imagefill($flattened, 0, 0, imagecolorallocate($flattened, 255, 255, 255));
        imagecopy($flattened, $source, 0, 0, 0, 0, $width, $height);
        imagedestroy($source);

        ob_start();
        $ok = imagejpeg($flattened, null, 85);
        $jpeg = ob_get_clean();
        imagedestroy($flattened);

        return $ok ? $jpeg : null;
    }

    private function makeThumbnail(string $jpegContent, int $maxWidth, int $maxHeight): ?string
    {
        $source = @imagecreatefromstring($jpegContent);
        if ($source === false) {
            return null;
        }

        $srcWidth = imagesx($source);
        $srcHeight = imagesy($source);
        $ratio = min($maxWidth / $srcWidth, $maxHeight / $srcHeight, 1);
        $dstWidth = max(1, (int) round($srcWidth * $ratio));
        $dstHeight = max(1, (int) round($srcHeight * $ratio));

        $thumb = imagecreatetruecolor($dstWidth, $dstHeight);
        imagecopyresampled($thumb, $source, 0, 0, 0, 0, $dstWidth, $dstHeight, $srcWidth, $srcHeight);
        imagedestroy($source);

        ob_start();
        $ok = imagejpeg($thumb, null, 85);
        $thumbContent = ob_get_clean();
        imagedestroy($thumb);

        return $ok ? $thumbContent : null;
    }

    private function usernameExists(string $username): bool
    {
        $db = $this->getDatabase();
        $query = $db->getQuery(true)
            ->select('COUNT(*)')
            ->from($db->quoteName('#__users'))
            ->where($db->quoteName('username') . ' = ' . $db->quote($username));
        return (bool) $db->setQuery($query)->loadResult();
    }

    private function loadUser(int $userId): User
    {
        return Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById($userId);
    }

    private function getCallbackUrl(): string
    {
        $root = rtrim(Uri::root(), '/');
        if (str_starts_with($root, 'http://')) {
            $root = 'https://' . substr($root, 7);
        }

        return $root . '/index.php?option=com_ajax&plugin=googleauth&group=system&format=raw';
    }

    private function redirectHome(string $message, string $type): void
    {
        $this->getApplication()->enqueueMessage($message, $type);
        $this->getApplication()->redirect(Uri::root());
    }

    /**
     * Success redirect after a Google login/registration, driven by the plugin's
     * "After sign-in" / "After first registration" settings.
     */
    private function redirectAfterLogin(string $message, string $returnUrl, bool $isNewUser): void
    {
        $this->getApplication()->enqueueMessage($message, 'message');

        try {
            $target = $this->resolveRedirectUrl($returnUrl, $isNewUser);
        } catch (\Throwable $e) {
            $this->log('error', 'redirect', 'Could not resolve redirect target: ' . $e->getMessage());
            $target = Uri::root();
        }

        $this->getApplication()->redirect($target !== '' ? $target : Uri::root());
    }

    private function resolveRedirectUrl(string $returnUrl, bool $isNewUser): string
    {
        $mode = (string) $this->params->get('redirect_login', 'current');
        $customUrl = (string) $this->params->get('redirect_login_url', '');

        if ($isNewUser) {
            $registerMode = (string) $this->params->get('redirect_register', 'same');

            if ($registerMode !== 'same') {
                $mode = $registerMode;
                $customUrl = (string) $this->params->get('redirect_register_url', '');
            }
        }

        switch ($mode) {
            case 'home':
                return Uri::root();

            case 'profile':
                return $this->getProfileUrl();

            case 'custom':
                return $this->normalizeCustomUrl($customUrl);

            case 'current':
            default:
                // Stay on the page the sign-in started from, but never bounce back to a
                // login screen or to a foreign host.
                if ($returnUrl === ''
                    || !Uri::isInternal($returnUrl)
                    || preg_match('/[?&]view=login(?:&|$)/', $returnUrl) === 1) {
                    return Uri::root();
                }

                return $returnUrl;
        }
    }

    /** Community Builder profile if CB is installed and enabled, otherwise the Joomla user profile. */
    private function getProfileUrl(): string
    {
        if ($this->isCommunityBuilderAvailable() && ComponentHelper::isEnabled('com_comprofiler')) {
            return Route::_('index.php?option=com_comprofiler&view=userprofile', false);
        }

        return Route::_('index.php?option=com_users&view=profile', false);
    }

    private function normalizeCustomUrl(string $url): string
    {
        $url = trim($url);

        if ($url === '') {
            return Uri::root();
        }

        if (preg_match('#^https?://#i', $url) === 1) {
            return $url;
        }

        if (str_starts_with($url, 'index.php?')) {
            return Route::_($url, false);
        }

        return rtrim(Uri::root(), '/') . '/' . ltrim($url, '/');
    }

    /**
     * Stores a new OAuth state alongside its timestamp, keeping several concurrently
     * valid states so that logging in from two tabs/windows does not clobber each other.
     */
    private function storeOauthState(string $state): void
    {
        $session = $this->getApplication()->getSession();
        $states = (array) $session->get(self::STATE_KEY, []);
        $now = time();

        // Drop anything expired while we're here so the session value doesn't grow forever.
        $states = array_filter($states, static fn ($timestamp) => ($now - (int) $timestamp) <= self::STATE_TTL);
        $states[$state] = $now;

        $session->set(self::STATE_KEY, $states);
    }

    /**
     * Validates and consumes a single OAuth state, removing it so it cannot be replayed.
     */
    private function consumeOauthState(string $state): bool
    {
        $session = $this->getApplication()->getSession();
        $states = (array) $session->get(self::STATE_KEY, []);

        if (!isset($states[$state])) {
            return false;
        }

        $timestamp = (int) $states[$state];
        unset($states[$state]);
        $session->set(self::STATE_KEY, $states);

        return (time() - $timestamp) <= self::STATE_TTL;
    }

    /**
     * Logs a plugin lifecycle event without ever writing secrets (client_secret,
     * access/ID tokens, passwords, or the raw Google profile) to the Joomla log.
     */
    private static bool $loggerRegistered = false;

    private function log(string $level, string $stage, string $message): void
    {
        try {
            if (!self::$loggerRegistered) {
                \Joomla\CMS\Log\Log::addLogger(
                    ['text_file' => 'googleauth.log.php'],
                    \Joomla\CMS\Log\Log::ALL,
                    ['googleauth']
                );
                self::$loggerRegistered = true;
            }

            \Joomla\CMS\Log\Log::add(
                sprintf('[%s] %s', $stage, $message),
                match ($level) {
                    'error' => \Joomla\CMS\Log\Log::ERROR,
                    'warning' => \Joomla\CMS\Log\Log::WARNING,
                    default => \Joomla\CMS\Log\Log::INFO,
                },
                'googleauth'
            );
        } catch (\Throwable $e) {
            // Logging must never break the auth flow.
        }
    }
}
