<?php

require 'Bca.php';

$check = 2;

if($check == 1) {

    // Token
    $headers = [];
    $headers["x-timestamp"] = "2023-06-16T11:33:48+07:00";
    $headers["x-client-key"] = "c822edca-0cbc-402e-bade-3dc108e63a27";
    $headers["x-signature"] = "zmYERCnd4ACotpkBvEpw7J6Bwjs3oHgwjGDJIRiHjAmmS7l/EtDiz5Xivb/GPhC4EpO4qSmnx35iD7OLslWMAFB2p2gzzo0WGG19bneKTOcXNFaCWKGW4pegLupx9eROFAaEDBWfecOPIHGyasIQlAUzgdVMSyusenZ3XT/JWQlhuY8FXTxyUqRLH1mp/OiDTPHHqaDZWCbd2P0Xw8PP72IfprzvdsiL97ReQjSK0TjEKbpvEQSrTJ8umH3QTp3SqmiQl2zVWy6ne1QcbUiuMNXTuywnjJPecnxzTftCMcNeYTGI1eLWxpJmuIyTyyyAM82zzpR72Z3ba7dPxbNw3g==";
    $headers["content-type"] = "application/json";
    
    $data = '{"grantType":"client_credentials"}';
    
    $response = $bca->getB2BToken($headers, $data);
    var_dump($response);

} elseif ($check == 2) {

    // Inquiry
    $headers = [];
    $headers["authorization"] = "Bearer CZIHCa1CHk4zt7TaMF8kyaQVCCpbqCQLNvE0QKEUn3Rn8fkI7fUDzq";
    $headers["x-timestamp"] = "2023-06-16T12:33:48+07:00";
    $headers["x-signature"] = "pWjxa7OY8Z9EckY6mOKgb8/9e2IEL0n0wcqOOiIr5HuIfog1rxBN5J9vCcTBBjBwc4KbMHF/fG/fELkZCbb9EA==";
    $headers["channel-id"] = "95231";
    $headers["x-partner-id"] = "12930";
    $headers["content-type"] = "application/json";

    $data = '{
        "partnerServiceId": "   14694",
        "customerNo": "223344",
        "virtualAccountNo": "   14694223344",
        "trxDateInit": "2023-06-13T11:55:01+07:00",
        "channelCode": 6014,
        "language": "",
        "amount": null,
        "hashedSourceAccountNo": "",
        "sourceBankCode": "014",
        "additionalInfo": {
            "value": ""
        },
        "passApp": "",
        "inquiryRequestId": "202306131232013810000041000001"
    }';

    $response = $bca->inquiry($headers, $data);
    var_dump($response);
    die;
} elseif ($check == 3) {

    // Payment
    $headers = [];
    $headers["authorization"] = "Bearer UZOeFd8DEJcLnG8qOrRkE3";
    $headers["x-timestamp"] = "2023-06-16T10:33:48+07:00";
    $headers["x-signature"] = "My1IXH9LEKKFfe+cUU7a8NoThHb3bcouaagupgnyhxaklk93cKVZU+v7m8u96Rrg1kUI8aeOx1slKI9kgzf3mg==";
    $headers["channel-id"] = "95231";
    $headers["x-partner-id"] = "12930";
    $headers["content-type"] = "application/json";

    $data = '{"partnerServiceId":"   14694","customerNo":"082131006006","virtualAccountNo":"   14694082131006006","virtualAccountName":"Olivia","virtualAccountEmail":"Olliviana0909@gmail.com","virtualAccountPhone":"082131006006","trxId":"","paymentRequestId":"202306131232013810000041000003","channelCode":6014,"hashedSourceAccountNo":"","sourceBankCode":"014","paidAmount":{"value":"10000.00","currency":"IDR"},"cumulativePaymentAmount":null,"paidBills":"","totalAmount":{"value":"10000.00","currency":"IDR"},"trxDateTime":"2023-06-13T13:09:01+07:00","referenceNo":"04100000101","journalNum":"","paymentType":"","flagAdvise":"N","subCompany":"00000","billDetails":[null],"freeTexts":[],"additionalInfo":{"value":""}}';

    $response = $bca->payment($headers, $data);
    var_dump($response);
} elseif ($check == 4) {

    // Generate Asymmetric Signature
    $headers = [];
    $headers["x-timestamp"] = "2023-06-16T11:33:48+07:00";
    $headers["x-client-key"] = "c822edca-0cbc-402e-bade-3dc108e63a27";
    
    $response = $bca->generateASign($headers);
    var_dump($response);
} elseif ($check == 5) {
    
    // Generate Symmetric Signature
    $headers = [];
    $headers["x-timestamp"] = "2023-06-16T12:33:48+07:00";

    $data = '{
        "partnerServiceId": "   14694",
        "customerNo": "223344",
        "virtualAccountNo": "   14694223344",
        "trxDateInit": "2023-06-13T11:55:01+07:00",
        "channelCode": 6014,
        "language": "",
        "amount": null,
        "hashedSourceAccountNo": "",
        "sourceBankCode": "014",
        "additionalInfo": {
            "value": ""
        },
        "passApp": "",
        "inquiryRequestId": "202306131232013810000041000001"
    }';

    $url = 'POST:/openapi/v1.0/transfer-va/inquiry';
    $access_token = 'CZIHCa1CHk4zt7TaMF8kyaQVCCpbqCQLNvE0QKEUn3Rn8fkI7fUDzq';
    $client_secret = '8cac0420-8657-4479-9d42-100889ac80c6';

    $response = $bca->generateSign($url, $access_token, $client_secret, $headers['x-timestamp'], $data);
    var_dump($response);
}