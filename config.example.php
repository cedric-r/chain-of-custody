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
 * Chain of Custody — Database and SMTP Configuration
 *
 * Copy this file to config.php (or tests/config.php) and fill in your
 * MySQL connection details. The SMTP settings are used by the web
 * interface for email verification during user registration.
 */
return [
    // Secret salt added to every SHA-256 hash. Generate with: php -r "echo bin2hex(random_bytes(16));"
    'hash_salt' => '',

    // MySQL database
    'host'     => '127.0.0.1',
    'port'     => 3306,
    'dbname'   => 'chain_of_custody',
    'username' => 'root',
    'password' => '',
    'charset'  => 'utf8mb4',

    // SMTP relay for outbound email (email verification)
    'smtp'     => [
        'host'               => '192.168.233.9',
        'port'               => 25,
        'auth'               => false,
        'from_email'         => 'noreply@chainofcustody.org',
        'from_name'          => 'Chain of Custody',
        'feedback_recipient' => '',   // Email that receives feedback form submissions
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
