<?php

class BcaHttp
{
    public static $VERSION = '2.3.1';

    /**
     * Default Timezone.
     *
     * @var string
     */
    private static $timezone = 'Asia/Jakarta';

    /**
     * Default BCA Port.
     *
     * @var int
     */
    private static $port = 443;

    /**
     * Default BCA Host.
     *
     * @var string
     */
    private static $hostName = 'devapi.klikbca.com';

    /**
     * Default BCA Host.
     *
     * @var string
     */
    private static $scheme = 'https';

    /**
     * Timeout curl.
     *
     * @var int
     */
    private static $timeOut = 60;

    /**
     * Default Curl Options.
     *
     * @var int
     */
    private static $curlOptions = array(
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_SSLVERSION => 6,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_TIMEOUT => 60
    );

    /**
     * Default BCA Settings.
     *
     * @var array
     */
    protected static $settings = array(
        'corp_id' => '',
        'client_id' => '',
        'client_secret' => '',
        'api_key' => '',
        'secret_key' => '',
        'private_key' => '',
        'curl_options' => array(),
        // Backward compatible
        'host' => 'devapi.klikbca.com',
        'scheme' => 'https',
        'timeout' => 60,
        'port' => 443,
        'timezone' => 'Asia/Jakarta',
        // New Options
        'options' => array(
            'host' => 'devapi.klikbca.com',
            'scheme' => 'https',
            'timeout' => 60,
            'port' => 443,
            'timezone' => 'Asia/Jakarta'
        )
    );
    
    private static $curlOpts = array();

    /**
     * Default Constructor.
     *
     * @param string $corp_id nilai corp id
     * @param string $client_id nilai client key
     * @param string $client_secret nilai client secret
     * @param string $api_key niali oauth key
     * @param string $secret_key nilai oauth secret
     * @param array $options opsi ke server bca
     */
    public function __construct($corp_id, $client_id, $client_secret, $api_key, $secret_key, $private_key, $public_key, array $options = [])
    {
        // Required parameters.
        self::$settings['corp_id'] = $corp_id;
        self::$settings['client_id'] = $client_id;
        self::$settings['client_secret'] = $client_secret;
        self::$settings['api_key'] = $api_key;
        self::$settings['secret_key'] = $secret_key;
        self::$settings['private_key'] = $private_key;
        self::$settings['public_key'] = $public_key;
        self::$settings['host'] =
            preg_replace('/http[s]?\:\/\//', '', self::$settings['host'], 1);

        foreach ($options as $key => $value) {
            if (isset(self::$settings[$key])) {
                self::$settings[$key] = $value;
            }
        }

        // Setup optional scheme, if scheme is empty
        if (isset($options['scheme'])) {
            self::$settings['scheme'] = $options['scheme'];
            self::$settings['options']['scheme'] = $options['scheme'];
        } else {
            self::$settings['scheme'] = self::getScheme();
            self::$settings['options']['scheme'] = self::getScheme();
        }

        // Setup optional host, if host is empty
        if (isset($options['host'])) {
            self::$settings['host'] = $options['host'];
            self::$settings['options']['host'] = $options['host'];
        } else {
            self::$settings['host'] = self::getHostName();
            self::$settings['options']['host'] = self::getHostName();
        }

        // Setup optional port, if port is empty
        if (isset($options['port'])) {
            self::$settings['port'] = $options['port'];
            self::$settings['options']['port'] = $options['port'];
        } else {
            self::$settings['port'] = self::getPort();
            self::$settings['options']['port'] = self::getPort();
        }

        // Setup optional timezone, if timezone is empty
        if (isset($options['timezone'])) {
            self::$settings['timezone'] = $options['timezone'];
            self::$settings['options']['timezone'] = $options['timezone'];
        } else {
            self::$settings['timezone'] = self::getHostName();
            self::$settings['options']['timezone'] = self::getHostName();
        }

        // Setup optional timeout, if timeout is empty
        if (isset($options['timeout'])) {
            self::$settings['timeout'] = $options['timeout'];
            self::$settings['options']['timeout'] = $options['timeout'];
        } else {
            self::$settings['timeout'] = self::getTimeOut();
            self::$settings['options']['timeout'] = self::getTimeOut();
        }

        // Set Default Curl Options.
        self::curlOpts(self::$curlOptions);

        // Set custom curl options
        if (!empty(self::$settings['curl_options'])) {
            $data = self::mergeCurlOptions(self::$curlOptions, self::$settings['curl_options']);
            self::curlOpts($data);
        }
    }

    /**
     * Set curl options to send on every request
     *
     * @param array $options options array
     * @return array
     */
    public static function curlOpts($options)
    {
        return self::mergeCurlOptions(self::$curlOpts, $options);
    }

    /**
     * @param array $existing_options
     * @param array $new_options
     * @return array
     */

    /**
     * Ambil Nilai settings.
     *
     * @return array
     */
    public function getSettings()
    {
        return self::$settings;
    }

    /**
     * Build the ddn domain.
     * output = 'https://sandbox.bca.co.id:443'
     * scheme = http(s)
     * host = sandbox.bca.co.id
     * port = 80 ? 443
     *
     * @return string
     */
    private function ddnDomain()
    {
        return self::$settings['scheme'] . '://' . self::$settings['host'] . ':' . self::$settings['port'] . '/';
    }

    /**
     * Generate Signature.
     *
     * @param string $url Url yang akan disign.
     * @param string $auth_token string nilai token dari login.
     * @param string $secret_key string secretkey yang telah diberikan oleh BCA.
     * @param string $isoTime string Waktu ISO8601.
     * @param array|mixed $bodyToHash array Body yang akan dikirimkan ke Server BCA.
     *
     * @return string
     */
    public static function callAPI($url, $method = 'GET', $data = array(), $headers = array())
    {
        $curl = curl_init();

        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_ENCODING, '');
        curl_setopt($curl, CURLOPT_MAXREDIRS, 10);
        curl_setopt($curl, CURLOPT_TIMEOUT, 0);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, strtoupper($method));
        curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        
        $response = curl_exec($curl);
        
        curl_close($curl);

        return $response;
    }

    /**
     * Generate authentifikasi ke server berupa OAUTH.
     *
     * @return \Unirest\Response
     */
    public function httpAuth()
    {
        $client_id = self::$settings['client_id'];
        $client_secret = self::$settings['client_secret'];

        $headerToken = base64_encode("$client_id:$client_secret");

        $headers = array(
            'Authorization: Basic ' . $headerToken,
            'Content-Type: application/x-www-form-urlencoded',
        );

        $request_path = "api/oauth/token";
        $domain = $this->ddnDomain();
        $full_url = $domain . $request_path;

        $data = array('grant_type' => 'client_credentials');
        $body = http_build_query($data);

        $response = self::callAPI($full_url, 'post', $body, $headers);

        return $response;
    }

    /**
     * Generate Signature.
     *
     * @param string $url Url yang akan disign.
     * @param string $auth_token string nilai token dari login.
     * @param string $secret_key string secretkey yang telah diberikan oleh BCA.
     * @param string $isoTime string Waktu ISO8601.
     * @param array|mixed $bodyToHash array Body yang akan dikirimkan ke Server BCA.
     *
     * @return string
     */
    public static function generateSign($url, $access_token, $client_secret, $isoTime, $bodyToHash = [])
    {
        $decodedBody = json_decode($bodyToHash);
        $minifiedJson = json_encode($decodedBody, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $sha256Hash = hash('sha256', $minifiedJson);
        $stringToSign = $url . ":" . $access_token . ":" . $sha256Hash . ":" . $isoTime;
        $auth_signature = hash_hmac('sha512', $stringToSign, $client_secret, true);
        $SymmetricSignature = base64_encode($auth_signature);
        return $SymmetricSignature;
    }

    public static function generateASign($headers)
    {
        $client_id = self::$settings['client_id'];
        $private_key = self::$settings['private_key'];
        $stringToSign = $client_id . '|' . $headers['x-timestamp'];
        $privateKeyResource = openssl_pkey_get_private($private_key);
        openssl_sign($stringToSign, $signature, $privateKeyResource, OPENSSL_ALGO_SHA256);
        openssl_free_key($privateKeyResource);

        $base64Signature = base64_encode($signature);
        return $base64Signature;
    }

    public static function verifyAsign($headers) {
        $client_id = self::$settings['client_id'];
        $publicKey = self::$settings['public_key'];
        $signature = $headers['x-signature'];
        $stringToSign = $client_id . '|' . $headers['x-timestamp'];
        $isValid = openssl_verify($stringToSign, base64_decode($signature), $publicKey, OPENSSL_ALGO_SHA256);
        return $isValid;
    }

    /**
     * Set TimeZone.
     *
     * @param string $timeZone Time yang akan dipergunakan.
     *
     * @return string
     */
    public static function setTimeZone($timeZone)
    {
        self::$timezone = $timeZone;
    }

    /**
     * Get TimeZone.
     *
     * @return string
     */
    public static function getTimeZone()
    {
        return self::$timezone;
    }

    /**
     * Set nama domain BCA yang akan dipergunakan.
     *
     * @param string $hostName nama domain BCA yang akan dipergunakan.
     *
     * @return string
     */
    public static function setHostName($hostName)
    {
        self::$hostName = $hostName;
    }

    /**
     * Ambil nama domain BCA yang akan dipergunakan.
     *
     * @return string
     */
    public static function getHostName()
    {
        return self::$hostName;
    }

    /**
     * Ambil maximum execution time.
     *
     * @return string
     */
    public static function getTimeOut()
    {
        return self::$timeOut;
    }

    /**
     * Ambil nama domain BCA yang akan dipergunakan.
     *
     * @return string
     */
    public static function getCurlOptions()
    {
        return self::$curlOptions;
    }

    /**
     * Setup curl options.
     *
     * @param array $curlOpts
     * @return array
     */
    public static function setCurlOptions(array $curlOpts = [])
    {
        $data = self::mergeCurlOptions(self::$curlOptions, $curlOpts);
        self::$curlOptions = $data;
    }

    /**
     * Set Ambil maximum execution time.
     *
     * @param int $timeOut timeout in milisecond.
     *
     * @return string
     */
    public static function setTimeOut($timeOut)
    {
        self::$timeOut = $timeOut;
        return self::$timeOut;
    }

    /**
     * Set BCA port
     *
     * @param int $port Port yang akan dipergunakan
     *
     * @return int
     */
    public static function setPort($port)
    {
        self::$port = $port;
    }

    /**
     * Get BCA port
     *
     * @return int
     */
    public static function getPort()
    {
        return self::$port;
    }

    /**
     * Set BCA Schema
     *
     * @param int $scheme Scheme yang akan dipergunakan
     *
     * @return string
     */
    public static function setScheme($scheme)
    {
        self::$scheme = $scheme;
    }

    /**
     * Get BCA Schema
     *
     * @return string
     */
    public static function getScheme()
    {
        return self::$scheme;
    }

    /**
     * Generate ISO8601 Time.
     *
     * @param string $timeZone Time yang akan dipergunakan
     *
     * @return string
     */
    public static function generateIsoTime()
    {
        $date = new \DateTime('now', new \DateTimeZone(self::getTimeZone()));
        $ISO8601 = $date->format('Y-m-d\TH:i:sP');

        return $ISO8601;
    }

    /**
     * Merge from existing array.
     *
     * @param array $existing_options
     * @param array $new_options
     * @return array
     */
    private static function mergeCurlOptions(&$existing_options, $new_options)
    {
        $existing_options = $new_options + $existing_options;
        return $existing_options;
    }

    /**
     * Validasi jika clientsecret telah di-definsikan.
     *
     * @param array $sourceAccountId
     *
     * @throws BcaHttpException Error jika array tidak memenuhi syarat
     * @return bool
     */
    private function validateArray($sourceAccountId = [])
    {
        if (!is_array($sourceAccountId)) {
            throw new BcaHttpException('Data harus array.');
        }
        if (empty($sourceAccountId)) {
            throw new BcaHttpException('AccountNumber tidak boleh kosong.');
        } else {
            $max = sizeof($sourceAccountId);
            if ($max > 20) {
                throw new BcaHttpException('Maksimal Account Number ' . 20);
            }
        }

        return true;
    }

    /**
     * Implode an array with the key and value pair giving
     * a glue, a separator between pairs and the array
     * to implode.
     *
     * @param string $glue The glue between key and value
     * @param string $separator Separator between pairs
     * @param array $array The array to implode
     *
     * @throws BcaHttpException error
     * @return string The imploded array
     */
    public static function arrayImplode($glue, $separator, $array = [])
    {
        if (!is_array($array)) {
            throw new BcaHttpException('Data harus array.');
        }
        if (empty($array)) {
            throw new BcaHttpException('parameter array tidak boleh kosong.');
        }
        foreach ($array as $key => $val) {
            if (is_array($val)) {
                $val = implode(',', $val);
            }
            $string[] = "{$key}{$glue}{$val}";
        }

        return implode($separator, $string);
    }
    
    public static function arrayExcept($array, $keys)
    {
        if (!is_array($keys)) {
            $keys = [$keys];
        }
    
        return array_intersect_key($array, array_flip($keys));
    }


    public static function response($code = '2002400', $msg=null, $data=null){
        $response = [];
        $response['responseCode'] = $code;
        $response['responseMessage'] = $msg;

        $errorCode = ['4007300', '4007301', '4007302', '4017300', '5047300', '4012400', '4002401', '4002402', '4002501', '4002502', '4002501', '4012500'];

        if (in_array($code, $errorCode)) {
            return $response;
        }
        
        if($code === '2007300') {
            $response['accessToken'] = $data['accessToken'];
            $response['tokenType'] = 'bearer';
            $response['expiresIn'] = 900;
            return $response;
        }

        $successCode = ['2002400', '4042412'];
        if(in_array($code, $successCode)) {
            $data['inquiryStatus'] = '00';
            $inquiryReason = [
                'english' => 'Success',
                'indonesia' => 'Sukses'
            ];

            if($code !== '2002400') {
                $keysToExclude = ['partnerServiceId', 'customerNo', 'virtualAccountNo', 'trxId','paymentRequestId'];
                $data = self::arrayExcept($data, $keysToExclude);
                $data['inquiryStatus'] = '01';
                $inquiryReason = [
                    'english' => 'Virtual account number is not registered',
                    'indonesia' => 'Nomor virtual akun tidak terdaftar'
                ];
            }

            $response['virtualAccountData'] = [
                'inquiryStatus' => $data['inquiryStatus'],
                'inquiryReason' => $inquiryReason,
                'partnerServiceId' => '   ' . trim($data['partnerServiceId']) ?? '',
                'customerNo' => $data['customerNo'] ?? '',
                'virtualAccountNo' => '   ' . trim($data['virtualAccountNo']) ?? '',
                'virtualAccountName' => '',
                'virtualAccountEmail' => '',
                'virtualAccountPhone' => '',
                'inquiryRequestId' => $data['inquiryRequestId'] ?? '',
                'totalAmount' => [
                    'value' => '',
                    'currency' => '',
                ],
                'subCompany' => '',
                'billDetails' => [],
                'freeTexts' => [
                    'english' => '',
                    'indonesia' => '',
                ],
                'virtualAccountTrxType' => '',
                'feeAmount' => [
                    'value' => '',
                    'currency' => '',
                ],
                'additionalInfo' => [
                    'deviceId' => '',
                    'channel' => '',
                ],
            ];
            ksort($data);
            return $response;
        }

        
        $successCode = ['2002500', '4042512'];
        if(in_array($code, $successCode)) {
            $data['paymentFlagStatus'] = '00';
            if($code !== '2002500') {
                $keysToExclude = ['partnerServiceId', 'customerNo', 'virtualAccountNo', 'trxId','paymentRequestId'];
                $data = self::arrayExcept($data, $keysToExclude);
                $data['paymentFlagStatus'] = '01';
            }
            
            $response['virtualAccountData'] = [
                'paymentFlagReason' => [
                    'english' => '',
                    'indonesia' => '',
                ],
                'partnerServiceId' => '   ' . trim($data['partnerServiceId']) ?? '',
                'customerNo' => $data['customerNo'] ?? '',
                'virtualAccountNo' => '   ' . trim($data['virtualAccountNo']) ?? '',
                'virtualAccountName' => '',
                'virtualAccountEmail' => '',
                'virtualAccountPhone' => '',
                'trxId' => $data['trxId'] ?? '',
                'paymentRequestId' => $data['paymentRequestId'] ?? '',
                'paidAmount' => [
                    'value' => '',
                    'currency' => '',
                ],
                'paidBills' => '',
                'totalAmount' => [
                    'value' => '',
                    'currency' => '',
                ],
                'trxDateTime' => $data['trxDateTime'] ?? '',
                'referenceNo' => $data['referenceNo'] ?? '',
                'journalNum' => '',
                'paymentType' => '',
                'flagAdvise' => $data['flagAdvise'] ?? '',
                'paymentFlagStatus' => $data['paymentFlagStatus'] ?? '01',
                'billDetails' => [],
                'freeTexts' => [[
                    'english' => 'Free text',
                    'indonesia' => 'Tulisan bebas',
                ]],
            ];
            ksort($response);
            $response['additionalInfo'] = (object)[];
            $jsonResponse = json_encode($response);
            return $response;
        }
    }

    /**
     * Ambil informasi B2B Token.
     *
     * @param string $oauth_token nilai token yang telah didapatkan setelah login
     *
     * @throws BcaHttpException error
     * @return \Unirest\Response
     */
    public function getB2BToken($headers, $data)
    {
        $client_id = self::$settings['client_id'];
        $client_secret = self::$settings['client_secret'];
        $request = (array) json_decode($data);

        if(!isset($headers['x-client-key'])) {
            $response['responseCode'] = '4007302';
            $response['responseMessage'] = 'Invalid mandatory field [clientId/clientSecret/grantType]';
            return self::response($response['responseCode'], $response['responseMessage']);
        }

        if($client_id !== $headers['x-client-key']) {
            $response['responseCode'] = '4017300';
            $response['responseMessage'] = 'Unauthorized. [Unknown client]';
            return self::response($response['responseCode'], $response['responseMessage']);
        }

        if (isset($headers['x-timestamp'])) {
            $dateTime = DateTime::createFromFormat(DateTime::ATOM, $headers['x-timestamp']);
            $currentDateTime = new \DateTime('now', new \DateTimeZone(self::getTimeZone()));

            if (!$dateTime || $dateTime->format('Y-m-d H') != $currentDateTime->format('Y-m-d H')) {
                $response['responseCode'] = '4007301';
                $response['responseMessage'] = 'invalid timestamp format [X-TIMESTAMP]';
                return self::response($response['responseCode'], $response['responseMessage']);
            }
        } else {
            $response['responseCode'] = '4007301';
            $response['responseMessage'] = 'invalid timestamp format [X-TIMESTAMP]';
            return self::response($response['responseCode'], $response['responseMessage']);
        }

        $verifyAsign = self::verifyAsign($headers);
        if($verifyAsign === 0 && !isset($headers['debug'])) {
            $response['responseCode'] = '4017300';
            $response['responseMessage'] = 'Unauthorized. [Signature]';
            return self::response($response['responseCode'], $response['responseMessage']);
        }
        
        if(!isset($request['grantType'])) {
            $response['responseCode'] = '4007300';
            $response['responseMessage'] = 'Invalid field format[clientId/clientSecret/grantType]';
            return self::response($response['responseCode'], $response['responseMessage']);
        }

        $tokenJson = self::httpAuth();
        $token = json_decode($tokenJson);
        
        if(!isset($token->access_token)) {
            $response['responseCode'] = '5047300';
            $response['responseMessage'] = 'Timeout';
            return self::response($response['responseCode'], $response['responseMessage']);
        }
        
        $response['responseCode'] = '2007300';
        $response['responseMessage'] = 'Successful';
        
        $data = [];
        $data['accessToken'] = $token->access_token;

        return self::response($response['responseCode'], $response['responseMessage'], $data);
    }

    public function inquiry($headers, $data)
    {
        $corp_id = self::$settings['corp_id'];
        $client_secret = self::$settings['client_secret'];
        $request = (array) json_decode($data);
        if(!isset($request['partnerServiceId'])) {
            $response['responseCode'] = '4002402';
            $response['responseMessage'] = 'Missing Mandatory Field [partnerServiceId]';
            return self::response($response['responseCode'], $response['responseMessage']);
        } elseif(!isset($request['customerNo'])) {
            $response['responseCode'] = '4002402';
            $response['responseMessage'] = 'Missing Mandatory Field [customerNo]';
            return self::response($response['responseCode'], $response['responseMessage']);
        } elseif(!isset($request['virtualAccountNo'])) {
            $response['responseCode'] = '4002402';
            $response['responseMessage'] = 'Missing Mandatory Field [virtualAccountNo]';
            return self::response($response['responseCode'], $response['responseMessage']);
        } elseif(!isset($request['inquiryRequestId'])) {
            $response['responseCode'] = '4002402';
            $response['responseMessage'] = 'Missing Mandatory Field [inquiryRequestId]';
            return self::response($response['responseCode'], $response['responseMessage']);
        }

        
        if (isset($headers['x-timestamp'])) {
            $dateTime = DateTime::createFromFormat(DateTime::ATOM, $headers['x-timestamp']);
            $currentDateTime = new \DateTime('now', new \DateTimeZone(self::getTimeZone()));

            if (!$dateTime || $dateTime->format('Y-m-d H') != $currentDateTime->format('Y-m-d H')) {
                $response['responseCode'] = '4002401';
                $response['responseMessage'] = 'invalid timestamp format [X-TIMESTAMP]';
                return self::response($response['responseCode'], $response['responseMessage']);
            }
        } else {
            $response['responseCode'] = '4002401';
            $response['responseMessage'] = 'invalid timestamp format [X-TIMESTAMP]';
            return self::response($response['responseCode'], $response['responseMessage']);
        }

        $authorization = explode(' ', $headers['authorization'],2);
        $access_token = $authorization[1];
        $url = 'POST:/openapi/v1.0/transfer-va/inquiry';

        $symmetricSignature = self::generateSign($url, $access_token, $client_secret, $headers['x-timestamp'], $data);
        if($symmetricSignature !== $headers['x-signature']) {
            $response['responseCode'] = '4012400';
            $response['responseMessage'] = '"Unauthorized. 
            [Signature]';
            if(isset($headers['debug'])) {
                $response['signature'] = $symmetricSignature;
            }
            return self::response($response['responseCode'], $response['responseMessage']);
        }

        $response['responseCode'] = '2002400';
        $response['responseMessage'] = 'Successful';
        
        $data = [];
        $data['partnerServiceId'] = $request['partnerServiceId'];
        $data['customerNo'] = $request['customerNo'];
        $data['virtualAccountNo'] = $request['virtualAccountNo'];
        $data['inquiryRequestId'] = $request['inquiryRequestId'];
        
        if($corp_id != $request['partnerServiceId']) {
            $response['responseCode'] = '4042412';
            $response['responseMessage'] = 'Bill not found';
            return self::response($response['responseCode'], $response['responseMessage'], $data);
        }

        return self::response($response['responseCode'], $response['responseMessage'], $data);

    }

    public function payment($headers, $data)
    {
        $corp_id = self::$settings['corp_id'];
        $client_secret = self::$settings['client_secret'];
        $request = (array) json_decode($data);
        if(!isset($request['partnerServiceId'])) {
            $response['responseCode'] = '4002502';
            $response['responseMessage'] = 'Missing Mandatory Field [partnerServiceId]';
            return self::response($response['responseCode'], $response['responseMessage']);
        } elseif(!isset($request['customerNo'])) {
            $response['responseCode'] = '4002502';
            $response['responseMessage'] = 'Missing Mandatory Field [customerNo]';
            return self::response($response['responseCode'], $response['responseMessage']);
        } elseif(!isset($request['virtualAccountNo'])) {
            $response['responseCode'] = '4002502';
            $response['responseMessage'] = 'Missing Mandatory Field [virtualAccountNo]';
            return self::response($response['responseCode'], $response['responseMessage']);
        } elseif(!isset($request['paymentRequestId'])) {
            $response['responseCode'] = '4002502';
            $response['responseMessage'] = 'Missing Mandatory Field [paymentRequestId]';
            return self::response($response['responseCode'], $response['responseMessage']);
        } elseif(!isset($request['paidAmount'])) {
            $response['responseCode'] = '4002502';
            $response['responseMessage'] = 'Missing Mandatory Field [paidAmount]';
            return self::response($response['responseCode'], $response['responseMessage']);
        } elseif(!isset($request['flagAdvise'])) {
            $response['responseCode'] = '4002502';
            $response['responseMessage'] = 'Missing Mandatory Field [flagAdvise]';
            return self::response($response['responseCode'], $response['responseMessage']);
        }

        
        if (isset($headers['x-timestamp'])) {
            $dateTime = DateTime::createFromFormat(DateTime::ATOM, $headers['x-timestamp']);
            $currentDateTime = new \DateTime('now', new \DateTimeZone(self::getTimeZone()));

            if (!$dateTime || $dateTime->format('Y-m-d H') != $currentDateTime->format('Y-m-d H')) {
                $response['responseCode'] = '4002501';
                $response['responseMessage'] = 'invalid timestamp format [X-TIMESTAMP]';
                return self::response($response['responseCode'], $response['responseMessage']);
            }
        } else {
            $response['responseCode'] = '4002501';
            $response['responseMessage'] = 'invalid timestamp format [X-TIMESTAMP]';
            return self::response($response['responseCode'], $response['responseMessage']);
        }

        $authorization = explode(' ', $headers['authorization'],2);
        $access_token = $authorization[1];
        $url = 'POST:/openapi/v1.0/transfer-va/payment';

        $symmetricSignature = self::generateSign($url, $access_token, $client_secret, $headers['x-timestamp'], $data);
        if($symmetricSignature !== $headers['x-signature']) {
            $response['responseCode'] = '4012500';
            $response['responseMessage'] = '"Unauthorized. 
            [Signature]';
            if(isset($headers['debug'])) {
                $response['signature'] = $symmetricSignature;
            }
            
            return self::response($response['responseCode'], $response['responseMessage']);
        }

        $response['responseCode'] = '2002500';
        $response['responseMessage'] = 'Successful';
        
        $data = [];
        $data['partnerServiceId'] = $request['partnerServiceId'];
        $data['customerNo'] = $request['customerNo'];
        $data['virtualAccountNo'] = $request['virtualAccountNo'];
        $data['paymentRequestId'] = $request['paymentRequestId'];
        $data['paidAmount'] = $request['paidAmount'];
        $data['flagAdvise'] = $request['flagAdvise'];

        if($corp_id !== '302') {
            $response['responseCode'] = '4042512';
            $response['responseMessage'] = 'Bill not found';
            $data['inquiryStatus'] = '00';
            return self::response($response['responseCode'], $response['responseMessage'], $data);
        }

        $data['inquiryStatus'] = '01';
        return self::response($response['responseCode'], $response['responseMessage'], $data);

    }
}
