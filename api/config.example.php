<?php

declare(strict_types=1);

/**
 * Chain of Custody — API Database Configuration
 */
return [
    'node_id'   => '',
    'hash_salt' => '',
    'host'     => '127.0.0.1',
    'port'     => 3306,
    'dbname'   => 'chain_of_custody',
    'username' => 'custody_user',
    'password' => 'custody$password',
    'charset'  => 'utf8mb4',
];
