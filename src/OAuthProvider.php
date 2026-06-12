<?php

declare(strict_types=1);

/**
 * Copyright © 2026 Cedric Raguenaud <cedric@raguenaud.earth>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * Chain of Custody — OAuth authentication helpers.
 *
 * Handles authorization URL generation, token exchange, and user-info
 * retrieval for Google and GitHub OAuth 2.0 providers.
 *
 * Usage:
 *   $url = OAuthProvider::getAuthorizationUrl('google', $oauthConfig);
 *   $token = OAuthProvider::exchangeCode('google', $_GET['code'], $oauthConfig);
 *   $user = OAuthProvider::getUserInfo('google', $token, $oauthConfig);
 */

class OAuthProvider
{
    // ------------------------------------------------------------------
    //  Provider metadata
    // ------------------------------------------------------------------

    private const PROVIDERS = [
        'google' => [
            'authorize_url' => 'https://accounts.google.com/o/oauth2/v2/auth',
            'token_url'     => 'https://oauth2.googleapis.com/token',
            'userinfo_url'  => 'https://www.googleapis.com/oauth2/v2/userinfo',
            'scopes'        => 'email profile',
        ],
        'github' => [
            'authorize_url' => 'https://github.com/login/oauth/authorize',
            'token_url'     => 'https://github.com/login/oauth/access_token',
            'userinfo_url'  => 'https://api.github.com/user',
            'scopes'        => 'user:email',
        ],
    ];

    // ------------------------------------------------------------------
    //  Public API
    // ------------------------------------------------------------------

    /**
     * Get the provider's config array, or throw if not configured.
     *
     * @param  string  $provider  Provider name (google, github).
     * @param  array   $oauthCfg  The 'oauth' section from config.
     * @return array              Provider-specific config.
     * @throws RuntimeException   When the provider is unknown or not configured.
     */
    public static function getProviderConfig(string $provider, array $oauthCfg): array
    {
        if (!isset(self::PROVIDERS[$provider])) {
            throw new RuntimeException("Unknown OAuth provider: {$provider}");
        }

        $cfg = $oauthCfg[$provider] ?? [];

        if (empty($cfg['client_id']) || empty($cfg['client_secret'])) {
            throw new RuntimeException(
                "OAuth provider '{$provider}' is not configured (missing client_id or client_secret)."
            );
        }

        return $cfg;
    }

    /**
     * Build the URL to redirect the user to the provider's consent page.
     *
     * @param  string  $provider   Provider name.
     * @param  array   $oauthCfg   The 'oauth' section from config.
     * @param  string  $state      Random CSRF token stored in session.
     * @return string              Absolute URL to redirect to.
     */
    public static function getAuthorizationUrl(string $provider, array $oauthCfg, string $state): string
    {
        $meta     = self::PROVIDERS[$provider];
        $cfg      = self::getProviderConfig($provider, $oauthCfg);
        $params   = http_build_query([
            'client_id'     => $cfg['client_id'],
            'redirect_uri'  => $cfg['redirect_uri'],
            'response_type' => 'code',
            'scope'         => $meta['scopes'],
            'state'         => $state,
            'access_type'   => 'offline',    // Google-specific; GitHub ignores it
            'prompt'        => 'consent',     // Forces Google to always show consent
        ]);

        return $meta['authorize_url'] . '?' . $params;
    }

    /**
     * Exchange the authorization code for an access token.
     *
     * @coverage-exclude: Requires real HTTP calls to Google/GitHub OAuth endpoints.
     *
     * @param  string  $provider   Provider name.
     * @param  string  $code       The 'code' query parameter from the callback.
     * @param  array   $oauthCfg   The 'oauth' section from config.
     * @return string              Access token.
     * @throws RuntimeException    When the token exchange fails.
     */
    public static function exchangeCode(string $provider, string $code, array $oauthCfg): string
    {
        $meta = self::PROVIDERS[$provider];
        $cfg  = self::getProviderConfig($provider, $oauthCfg);

        $postData = http_build_query([
            'code'          => $code,
            'client_id'     => $cfg['client_id'],
            'client_secret' => $cfg['client_secret'],
            'redirect_uri'  => $cfg['redirect_uri'],
            'grant_type'    => 'authorization_code',
        ]);

        $context = stream_context_create([
            'http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: application/x-www-form-urlencoded\r\n"
                           . "Accept: application/json\r\n",
                'content' => $postData,
                'timeout' => 15,
            ],
        ]);

        $response = @file_get_contents($meta['token_url'], false, $context);

        if ($response === false) {
            throw new RuntimeException("Failed to exchange code with {$provider}.");
        }

        $data = json_decode($response, true);

        if (!isset($data['access_token'])) {
            $error = $data['error_description'] ?? $data['error'] ?? 'unknown error';
            throw new RuntimeException("{$provider} token exchange failed: {$error}");
        }

        return $data['access_token'];
    }

    /**
     * Fetch the user's profile from the provider using an access token.
     *
     * @coverage-exclude: Requires real HTTP calls to Google/GitHub userinfo endpoints.
     *
     * @param  string  $provider     Provider name.
     * @param  string  $accessToken  Access token from exchangeCode().
     * @param  array   $oauthCfg     The 'oauth' section from config.
     * @return array{id: string, email: string, name: string}
     * @throws RuntimeException      When the userinfo request fails.
     */
    public static function getUserInfo(string $provider, string $accessToken, array $oauthCfg): array
    {
        $meta = self::PROVIDERS[$provider];

        $context = stream_context_create([
            'http' => [
                'header' => "Authorization: Bearer {$accessToken}\r\n"
                          . "Accept: application/json\r\n"
                          . "User-Agent: ChainOfCustody/1.0\r\n",
                'timeout' => 15,
            ],
        ]);

        $response = @file_get_contents($meta['userinfo_url'], false, $context);

        if ($response === false) {
            throw new RuntimeException("Failed to fetch user info from {$provider}.");
        }

        $data = json_decode($response, true);

        if ($provider === 'google') {
            return [
                'id'    => $data['id'] ?? '',
                'email' => $data['email'] ?? '',
                'name'  => $data['name'] ?? '',
            ];
        }

        if ($provider === 'github') {
            $email = $data['email'] ?? '';
            $id    = (string) ($data['id'] ?? '');
            $name  = $data['name'] ?? $data['login'] ?? '';

            // GitHub may not return the primary email in the user endpoint
            if ($email === '') {
                $email = self::fetchGitHubPrimaryEmail($accessToken);
            }

            return [
                'id'    => $id,
                'email' => $email,
                'name'  => $name,
            ];
        }

        throw new RuntimeException("Unsupported provider: {$provider}");
    }

    // ------------------------------------------------------------------
    //  Provider-specific helpers
    // ------------------------------------------------------------------

    /**
     * Fetch the user's primary email from GitHub's /user/emails endpoint.
     *
     * @coverage-exclude: Requires real HTTP calls to api.github.com.
     */
    private static function fetchGitHubPrimaryEmail(string $accessToken): string
    {
        $context = stream_context_create([
            'http' => [
                'header' => "Authorization: Bearer {$accessToken}\r\n"
                          . "Accept: application/json\r\n"
                          . "User-Agent: ChainOfCustody/1.0\r\n",
                'timeout' => 15,
            ],
        ]);

        $response = @file_get_contents('https://api.github.com/user/emails', false, $context);

        if ($response === false) {
            return '';
        }

        $emails = json_decode($response, true);

        if (!is_array($emails)) {
            return '';
        }

        foreach ($emails as $entry) {
            if (!empty($entry['primary']) && !empty($entry['verified'])) {
                return $entry['email'] ?? '';
            }
        }

        return $emails[0]['email'] ?? '';
    }
}
