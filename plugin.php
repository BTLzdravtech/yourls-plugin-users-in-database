<?php
/*
Plugin Name: Users in Database
Plugin URI:
Description: Puts users in the database
Version: 1.0
Author: Nick Bair - revised by Martin Kolb
Author URI: https://github.com/njbair
Author URI: https://github.com/ediathome
*/

use PDO;

yourls_add_action( 'pre_login', 'uidb_pre_login' );

function uidb_pre_login() {
    global $yourls_user_passwords, $amp_role_assignment, $ydb;

    try {
        $prefix = YOURLS_DB_PREFIX;

        uidb_create_users_table_if_missing($ydb);

        $stmt = $ydb->query("SELECT username,password,role FROM ${prefix}users");
        $rows = $stmt->fetchAll();

        //var_export($rows); die();
    } catch (PDOException $e) {
        yourls_die ( yourls__( 'Could not connect to database.' ), yourls__( 'Fatal error' ), 503 );
    }

    $yourls_user_passwords = array();
    foreach ($rows as $row) {
        $yourls_user_passwords[$row['username']] = $row['password'];
        if(isset($row['role'])) {
            $amp_role_assignment[$row['role']][] = $row['username'];
        }
    }

    uidb_hash_passwords_now($ydb);
}

function uidb_connect_to_database() {
    $dbhost = YOURLS_DB_HOST;
    $user   = YOURLS_DB_USER;
    $pass   = YOURLS_DB_PASS;
    $dbname = YOURLS_DB_NAME;

    // Get custom port if any
    if ( false !== strpos( $dbhost, ':' ) ) {
        list( $dbhost, $dbport ) = explode( ':', $dbhost );
        $dbhost = sprintf( '%1$s;port=%2$d', $dbhost, $dbport );
    }

    $charset = yourls_apply_filter( 'db_connect_charset', 'utf8' );
    $dsn = sprintf( 'mysql:host=%s;dbname=%s;charset=%s', $dbhost, $dbname, $charset );
    $dsn = yourls_apply_filter( 'db_connect_custom_dsn', $dsn );
    $driver_options = yourls_apply_filter( 'db_connect_driver_option', array() ); // driver options as key-value pairs

    try {
        $db = new PDO( $dsn, $user, $pass, $driver_options );
    } catch (PDOException $e) {
        echo $e->getMessage();
    }

    return $db;
}

function uidb_create_users_table_if_missing($db) {
    try {
        $prefix = YOURLS_DB_PREFIX;
        $charset = yourls_apply_filter( 'db_connect_charset', 'utf8' );
        $sql = <<<EOT
CREATE TABLE IF NOT EXISTS `${prefix}users` (
    id INTEGER PRIMARY KEY AUTOINCREMENT NULL,
    username varchar(200),
    role varchar(200),
    password varchar(255)
);
EOT;

        $db->exec($sql);
    } catch(PDOException $e) {
        echo $e->getMessage();
    }
}

function uidb_hash_passwords_now($db) {
    global $yourls_user_passwords;

    $prefix = YOURLS_DB_PREFIX;

    $to_hash = array(); // keep track of number of passwords that need hashing
    foreach ( $yourls_user_passwords as $user => $password ) {
        if ( !yourls_has_phpass_password( $user ) && !yourls_has_md5_password( $user ) ) {
            $hash = yourls_phpass_hash( $password );
            // PHP would interpret $ as a variable, so replace it in storage.
            $hash = str_replace( '$', '!', $hash );

            $to_hash[$user] = $hash;
        }
    }

    if( empty($to_hash) )
        return 0; // There was no password to encrypt

    foreach ($to_hash as $user => $hash) {
        $stmt = $db->prepare("UPDATE ${prefix}users SET password=? WHERE username=?");
        $stmt->execute([ 'phpass:' . $hash, $user ]);
    }

    return true;
}
