<?php

declare(strict_types=1);

/**
 * Chain of Custody — Website Database, SMTP and OAuth Configuration
 */
return [
    'hash_salt' => '',
    'host'     => '127.0.0.1',
    'port'     => 3306,
    'dbname'   => 'chain_of_custody',
    'username' => 'custody_user',
    'password' => 'custody$password',
    'charset'  => 'utf8mb4',

    'smtp'     => [
        'host'               => '192.168.233.9',
        'port'               => 25,
        'auth'               => false,
        'from_email'         => 'noreply@raguenaud.org',
        'from_name'          => 'Chain of Custody',
        'feedback_recipient' => '',
    ],

    // OAuth provider credentials (optional — omit for local-only auth)
    'oauth' => [
        'google' => [
            'client_id'     => '',
            'client_secret' => '',
            'redirect_uri'  => 'https://photo-verify.org/?action=oauth_callback&provider=google',
        ],
        'github' => [
            'client_id'     => '',
            'client_secret' => '',
            'redirect_uri'  => 'https://photo-verify.org/?action=oauth_callback&provider=github',
        ],
    ],
];
