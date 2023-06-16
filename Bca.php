<?php
require 'BcaHttp.php';

$company_code = "COMPANY-CODE";
$client_key = "CLIENT-KEY";
$client_secret = "CLIENT-SECRET";
$apikey = "API-KEY"; // optional
$secret = "API-SECRET"; // optional
$privateKey = file_get_contents('private_key.pem');
$publicKey = file_get_contents('public_key.pem');

$bca = new BcaHttp($company_code, $client_key, $client_secret, $apikey, $secret, $privateKey, $publicKey);