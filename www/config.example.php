<?php

declare(strict_types=1);

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
        'host'       => '192.168.233.9',
        'port'       => 25,
        'auth'       => false,
        'from_email' => 'noreply@chainofcustody.org',
        'from_name'  => 'Chain of Custody',
        'feedback_recipient' => '',   // Email address that receives feedback form submissions
    ],
];
