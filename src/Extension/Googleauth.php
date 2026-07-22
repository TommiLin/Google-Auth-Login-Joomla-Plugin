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

use Joomla\CMS\Factory;
use Joomla\CMS\Http\HttpFactory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Plugin\CMSPlugin;
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

        $body = $app->getBody();
        $formPattern = '#(<form[^>]*(?:cbLoginForm|mod-login|login-form|com_comprofiler|jrForm)[^>]*>.*?</form>)#is';

        if (!preg_match($formPattern, $body, $formMatches)) {
            return;
        }

        $state = bin2hex(random_bytes(32));
        $app->getSession()->set(self::STATE_KEY, $state);

        $googleUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query([
            'client_id' => $clientId,
            'redirect_uri' => $this->getCallbackUrl(),
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'state' => $state,
            'prompt' => 'select_account',
        ], '', '&', PHP_QUERY_RFC3986);

        $this->loadLanguage();
        $buttonText = Text::_('PLG_SYSTEM_GOOGLEAUTH_LOGIN_BUTTON');

        $buttonHtml = '<div class="google-auth-container" style="flex-basis:100%;width:100%;margin-top:12px;clear:both;">'
          . '<a href="' . htmlspecialchars($googleUrl, ENT_QUOTES, 'UTF-8') . '" class="google-login-btn" '
             . 'style="display:flex;align-items:center;justify-content:center;gap:12px;width:100%;min-height:40px;'
             . 'padding:10px 16px;box-sizing:border-box;'
              . 'background:#fff;border:1px solid #dadce0;border-radius:4px;'
              . 'color:#3c4043;text-decoration:none;font:inherit;font-weight:500;line-height:1.4;">'

              . '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="18" height="18" aria-hidden="true">'
              . '<path fill="#EA4335" d="M24 9.5c3.54 0 6.72 1.22 9.22 3.61l6.9-6.9C35.9 2.3 30.4 0 24 0 14.64 0 6.56 5.38 2.56 13.22l8.04 6.24C12.53 13.52 17.8 9.5 24 9.5z"/>'
              . '<path fill="#4285F4" d="M46.98 24.55c0-1.57-.14-3.08-.4-4.55H24v9.09h12.94c-.56 2.98-2.24 5.5-4.77 7.18l7.73 6C44.4 38.1 46.98 31.84 46.98 24.55z"/>'
              . '<path fill="#FBBC05" d="M10.6 28.54A14.5 14.5 0 0 1 9.5 24c0-1.58.39-3.08 1.1-4.54l-8.04-6.24A23.95 23.95 0 0 0 0 24c0 3.87.93 7.52 2.56 10.78l8.04-6.24z"/>'
             . '<path fill="#34A853" d="M24 48c6.48 0 11.92-2.14 15.9-5.82l-7.73-6c-2.15 1.45-4.9 2.32-8.17 2.32-6.2 0-11.47-4.02-13.4-9.46l-8.04 6.24C6.56 42.62 14.64 48 24 48z"/>'
             . '</svg>'

               . '<span>' . htmlspecialchars($buttonText, ENT_QUOTES, 'UTF-8') . '</span>'
             . '</a></div>';

    $loginFormHtml = $formMatches[1];
    $submitPattern = '#(<div[^>]*(?:submit|control-group|actions|fwd-justify-end)[^>]*>.*?</div>)#is';
    $fixedLoginFormHtml = preg_match($submitPattern, $loginFormHtml, $match)
    ? str_replace($match[1], $match[1] . $buttonHtml, $loginFormHtml)
    : preg_replace('#</form>#i', $buttonHtml . '</form>', $loginFormHtml, 1);
    $hoverCss = '
    <style>
        .google-login-btn{
           transition:box-shadow .2s ease;
        }

        .google-login-btn:hover{
           border-top-color:#dadce0 !important;
           border-right-color:#c6c6c6 !important;
           border-bottom-color:#c6c6c6 !important;
           border-left-color:#c6c6c6 !important;

         text-decoration:none !important;

          box-shadow:
                0 3px 6px -2px rgba(60,64,67,.30),
                2px 2px 3px -2px rgba(60,64,67,.18),
               -2px 2px 3px -2px rgba(60,64,67,.18);
        }
</style>';

    $body = str_replace('</head>', $hoverCss . '</head>', $body);
    $app->setBody(str_replace($loginFormHtml, $fixedLoginFormHtml, $body));
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
        $expectedState = (string) $session->get(self::STATE_KEY, '');
        $session->clear(self::STATE_KEY);

        if ($code === '' || $expectedState === '' || !hash_equals($expectedState, $state)) {
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_STATE'), 'error');
            return;
        }

        try {
            $http = HttpFactory::getHttp();
            $tokenRequest = http_build_query([
                'code' => $code,
                'client_id' => trim((string) $this->params->get('client_id')),
                'client_secret' => trim((string) $this->params->get('client_secret')),
                'redirect_uri' => $this->getCallbackUrl(),
                'grant_type' => 'authorization_code',
            ], '', '&', PHP_QUERY_RFC3986);
            $tokenResponse = $http->post('https://oauth2.googleapis.com/token', $tokenRequest, [
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Accept' => 'application/json',
            ]);
            $tokenData = json_decode($tokenResponse->body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_CONNECT'), 'error');
            return;
        }

        if (!$this->isSuccessfulResponse($tokenResponse) || empty($tokenData['access_token'])) {
            $this->redirectHome($this->getGoogleErrorMessage($tokenData, Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_TOKEN_REJECTED')), 'error');
            return;
        }

        try {
            $profileResponse = $http->get(
                'https://openidconnect.googleapis.com/v1/userinfo',
                ['Authorization' => 'Bearer ' . $tokenData['access_token'], 'Accept' => 'application/json']
            );
            $profile = json_decode($profileResponse->body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_PROFILE_FETCH'), 'error');
            return;
        }

        $email = strtolower(trim((string) ($profile['email'] ?? '')));
        $googleId = trim((string) ($profile['sub'] ?? ''));
        $emailVerified = filter_var($profile['email_verified'] ?? false, FILTER_VALIDATE_BOOLEAN);
        $avatarUrl = trim((string) ($profile['picture'] ?? ($profile['image'] ?? '')));

        if (!$this->isSuccessfulResponse($profileResponse)) {
            $this->redirectHome($this->getGoogleErrorMessage($profile, Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_PROFILE_REJECTED')), 'error');
            return;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !$emailVerified || $googleId === '') {
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_EMAIL_UNVERIFIED'), 'error');
            return;
        }

        try {
            $result = $this->findOrCreateUser($email, (string) ($profile['name'] ?? ''), $googleId, $avatarUrl);
        } catch (\Throwable $e) {
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_PREPARE_USER'), 'error');
            return;
        }

        if ($result === null) {
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_EMAIL_LINKED'), 'error');
            return;
        }

        if ($result['requiresConsent']) {
            $this->beginConsent((int) $result['user']->id, $googleId);
            return;
        }

        if (!$this->loginUser($result['user'])) {
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_LOGIN_DENIED'), 'error');
            return;
        }
        $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_MSG_SUCCESS'), 'message');
    }

    /** @return array{user: User, requiresConsent: bool}|null */
    private function findOrCreateUser(string $email, string $name, string $googleId, string $avatarUrl = ''): ?array
    {
        $user = $this->findUserByGoogleId($googleId);

if ($user !== null) {
    $this->syncCommunityBuilderUser((int) $user->id, $avatarUrl);

    return [
        'user' => $user,
        'requiresConsent' =>
            (bool) $this->params->get('require_consent', 1)
            && !$this->hasAcceptedTerms($user),
    ];
}

        $user = $this->findUserByEmail($email);
        if ($user !== null) {
            $storedGoogleId = (string) $user->getParam(self::GOOGLE_SUB_PARAM, '');
            if ($storedGoogleId !== '' && !hash_equals($storedGoogleId, $googleId)) {
                return null;
            }

            // Existing accounts are linked only after their previously recorded consent is found.
            if (!$this->hasAcceptedTerms($user)) {
                $this->syncCommunityBuilderUser((int) $user->id, $avatarUrl);
                return [
              'user' => $user,
                 'requiresConsent' =>
                  (bool) $this->params->get('require_consent', 1)
                 && !$this->hasAcceptedTerms($user),
];
            }

            $user->setParam(self::GOOGLE_SUB_PARAM, $googleId);
            if (!$user->save()) {
                throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_LINK_FAILED'));
            }
            $this->syncCommunityBuilderUser((int) $user->id, $avatarUrl);
            return ['user' => $user, 'requiresConsent' => false];
        }

        $user = new User();
        $user->set('name', $name !== '' ? $name : 'Google User');
        $user->set('username', $this->makeUniqueUsername($email));
        $user->set('email', $email);
        $user->set('password', UserHelper::hashPassword(bin2hex(random_bytes(32))));
        $user->set('groups', [2]);
        $user->set('block', 0);
        $user->set('activation', '');
        $user->set('registerDate', Factory::getDate()->toSql());
        $user->setParam(self::GOOGLE_SUB_PARAM, $googleId);
        if (!$user->save()) {
            throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_CREATE_FAILED'));
        }

        $this->syncCommunityBuilderUser((int) $user->id, $avatarUrl);
        $user = $this->loadUser((int) $user->id);

        return [
            'user' => $user,
            'requiresConsent' => (bool) $this->params->get('require_consent', 1),
        ];
    }

    private function beginConsent(int $userId, string $googleId): void
    {
        $token = bin2hex(random_bytes(32));
        $this->getApplication()->getSession()->set(self::PENDING_CONSENT_KEY, [
            'user_id' => $userId,
            'google_id' => $googleId,
            'token' => $token,
        ]);
        $this->getApplication()->redirect($this->getCallbackUrl() . '&task=consent');
    }

    private function handleConsent(): void
    {
        $this->loadLanguage();
        $app = $this->getApplication();
        $session = $app->getSession();
        $pending = $session->get(self::PENDING_CONSENT_KEY, []);
        $userId = (int) ($pending['user_id'] ?? 0);
        $googleId = (string) ($pending['google_id'] ?? '');
        $token = (string) ($pending['token'] ?? '');

        if ($userId <= 0 || $googleId === '' || $token === '') {
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_SESSION_EXPIRED'), 'warning');
            return;
        }

        if (strtoupper($app->input->getMethod()) !== 'POST') {
            $this->renderConsentPage($token);
            return;
        }

        $submittedToken = $app->input->post->getString('consent_token', '');
        $accepted = $app->input->post->getInt('accept_terms') === 1;
        if (!$accepted || !hash_equals($token, $submittedToken)) {
            $this->renderConsentPage($token, Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_CONSENT_REQUIRED'));
            return;
        }

        try {
            $user = $this->loadUser($userId);
            if ($user->id !== $userId) {
                throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_USER_NOT_FOUND'));
            }
            $storedGoogleId = (string) $user->getParam(self::GOOGLE_SUB_PARAM, '');
            if ($storedGoogleId !== '' && !hash_equals($storedGoogleId, $googleId)) {
                throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_ACCOUNT_MISMATCH'));
            }
            $user->setParam(self::GOOGLE_SUB_PARAM, $googleId);
            $user->setParam(self::PRIVACY_PARAM, json_encode([
                'accepted_terms' => true,
                'accepted_at' => gmdate('c'),
            ], JSON_THROW_ON_ERROR));
            if (!$user->save()) {
                throw new \RuntimeException(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_SAVE_CONSENT'));
            }
        } catch (\Throwable $e) {
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_SAVE_CONSENT_FAIL'), 'error');
            return;
        }

        $session->clear(self::PENDING_CONSENT_KEY);
        if (!$this->loginUser($user)) {
            $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_ERR_LOGIN_DENIED'), 'error');
            return;
        }
        $this->redirectHome(Text::_('PLG_SYSTEM_GOOGLEAUTH_MSG_CONSENT_SAVED'), 'message');
    }

    private function renderConsentPage(string $token, string $error = ''): void
{
    $this->loadLanguage();
    $message = $error === '' ? '' : '<p class="googleauth-error" role="alert">' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . '</p>';
    
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
        
$this->loadLanguage();

$html = '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    . '<title>' . Text::_('PLG_SYSTEM_GOOGLEAUTH_TITLE') . '</title><style>'
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
    . '<a href="/" class="googleauth-close" aria-label="' . Text::_('JCLOSE') . '">'
    . '<svg viewBox="0 0 24 24" aria-hidden="true">'
    . '<path d="M18.3 5.71a1 1 0 0 0-1.41 0L12 10.59 7.11 5.7A1 1 0 0 0 5.7 7.11L10.59 12l-4.9 4.89a1 1 0 1 0 1.42 1.41L12 13.41l4.89 4.89a1 1 0 0 0 1.41-1.41L13.41 12l4.89-4.89a1 1 0 0 0 0-1.4z"/>'
    . '</svg>'
    . '</a>'
    . '<h1 id="googleauth-title">' . Text::_('PLG_SYSTEM_GOOGLEAUTH_TITLE') . '</h1>'
    . '<p>' . Text::_('PLG_SYSTEM_GOOGLEAUTH_DESCRIPTION') . '</p>'
    . $message
    . '<form method="post" action="' . htmlspecialchars($this->getCallbackUrl() . '&task=consent', ENT_QUOTES, 'UTF-8') . '">'
    . '<input type="hidden" name="consent_token" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">'
    . '<label class="googleauth-check">'
    . '<input type="checkbox" name="accept_terms" value="1" required>'
    . '<span>' . sprintf(Text::_('PLG_SYSTEM_GOOGLEAUTH_TERMS_CHECKBOX'), $privacyLink, $termsLink) . '</span>'
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
        $session->set('com_users.mfa_checked', 0);
        $app->loadIdentity($user);

        if ($app->get('session_metadata', true)) {
            $app->checkSession();
        }

        $user->setLastVisit();
        return true;
    }

    private function hasAcceptedTerms(User $user): bool
    {
        $value = $user->getParam(self::PRIVACY_PARAM, '');
        $params = is_string($value) ? json_decode($value, true) : null;
        return is_array($params) && !empty($params['accepted_terms']);
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

    private function getGoogleErrorMessage(array $data, string $fallback): string
    {
        $description = trim((string) ($data['error_description'] ?? $data['error'] ?? ''));
        return $description !== '' ? 'Google OAuth: ' . $description : $fallback;
    }

    private function getConfiguredUrl(string $parameter): string
    {
        $url = trim((string) $this->params->get($parameter, ''));
        return filter_var($url, FILTER_VALIDATE_URL) && preg_match('#^https?://#i', $url) ? $url : '';
    }

    private function syncCommunityBuilderUser(int $userId, string $avatarUrl = ''): void
    {
        $db = $this->getDatabase();

        // Check if Community Builder is installed
        $tables = $db->getTableList();
        $prefix = $db->getPrefix();
        $cbTable = $prefix . 'comprofiler';

        if (!in_array($cbTable, $tables)) {
            return;
        }

        $oomlaUser = $this->loadUser($userId);
        $nameParts = explode(' ', trim($oomlaUser->name), 2);
        $firstName = $nameParts[0] ?? $oomlaUser->username;
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

        if ($avatarUrl !== '' && (!$exists || empty($cbUser->avatar))) {
            $imageContent = '';

            try {
                $http = HttpFactory::getHttp();
                $response = $http->get($avatarUrl);
                if ($this->isSuccessfulResponse($response) && !empty($response->body)) {
                    $imageContent = $response->body;
                }
            } catch (\Throwable $e) {
                // Ignore transport error
            }

            if (empty($imageContent)) {
                try {
                    $ctx = stream_context_create(['http' => ['method' => 'GET', 'timeout' => 5], 'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
                    $imageContent = @file_get_contents($avatarUrl, false, $ctx);
                } catch (\Throwable $e) {
                    $imageContent = '';
                }
            }

            if (!empty($imageContent)) {
                $uploadDir = JPATH_ROOT . '/images/comprofiler/';
                
                if (!is_dir($uploadDir)) {
                    mkdir($uploadDir, 0755, true);
                }
                
                $avatarFileName = $userId . '_' . substr(md5(uniqid('', true)), 0, 13) . '.jpg';
                $destination = $uploadDir . $avatarFileName;
                
                if (@file_put_contents($destination, $imageContent) !== false) {
                    @copy($destination, $uploadDir . 'tn' . $avatarFileName);
                } else {
                    $avatarFileName = ''; 
                }
            }
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
                ->values(implode(', ', [
                    (int) $userId,
                    (int) $userId,
                    1,
                    1,
                    $db->quote($firstName),
                    $db->quote($lastName),
                    ...($avatarFileName !== '' ? [$db->quote($avatarFileName), 1] : [])
                ]));
        }

        $db->setQuery($query);
        $db->execute();
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
}
