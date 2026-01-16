<?php
// ============================================================================
// webhook.php - RAILWAY WITH GET PARAMETER WORKAROUND
// Purpose: Receive Paychangu webhooks, verify, send to InfinityFree via GET
// ============================================================================
declare(strict_types=1);

date_default_timezone_set('Africa/Blantyre');

// ------------------------- CONFIG -------------------------
$paychanguSecretKey = getenv('secretkey');
$webhookSecret = getenv('WEBHOOK_SECRET');
$handlerUrl = getenv('HANDLER_URL');  // Should be: https://yazaitmw.great-site.net/webhook_processor.php
$handlerSecret = getenv('HANDLER_SECRET');

// ------------------------- LOGGING -------------------------
$logDir = __DIR__ . '/logs';
if (!is_dir($logDir)) {
    @mkdir($logDir, 0755, true);
}

function writeLog($type, $message) {
    global $logDir;
    $file = $logDir . '/' . $type . '.log';
    @file_put_contents($file, date('Y-m-d H:i:s') . " - " . $message . PHP_EOL, FILE_APPEND);
}

// ------------------------- HELPER FUNCTIONS -------------------------

if (!function_exists('getallheaders')) {
    function getallheaders() {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $header = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
                $headers[$header] = $value;
            }
        }
        return $headers;
    }
}

function getHeader($headers, $name) {
    foreach ($headers as $key => $value) {
        if (strcasecmp($key, $name) === 0) {
            return $value;
        }
    }
    return null;
}

// ------------------------- STEP 1: RECEIVE WEBHOOK -------------------------
$payload = file_get_contents('php://input');
$headers = getallheaders();

writeLog('debug', "Received webhook");

// ------------------------- STEP 2: VALIDATE SIGNATURE -------------------------
$signature = getHeader($headers, 'Signature') ?? $_SERVER['HTTP_SIGNATURE'] ?? null;

if (!$signature) {
    http_response_code(400);
    writeLog('suspicious', "REJECTED: Missing Signature header");
    exit("Missing Signature header");
}

$computedSignature = hash_hmac('sha256', $payload, $webhookSecret);

if (!hash_equals($computedSignature, $signature)) {
    http_response_code(403);
    writeLog('suspicious', "REJECTED: Invalid signature");
    exit("Invalid signature");
}

writeLog('received', "✓ Valid signature from Paychangu");

// ------------------------- STEP 3: PARSE PAYLOAD -------------------------
$webhookData = json_decode($payload, true);

if (!$webhookData || !isset($webhookData['tx_ref'])) {
    http_response_code(400);
    writeLog('suspicious', "REJECTED: Invalid JSON payload");
    exit("Invalid payload");
}

$tx_ref = $webhookData['tx_ref'];
$paymentStatus = $webhookData['status'] ?? null;

writeLog('received', "Webhook for tx_ref: $tx_ref, status: $paymentStatus");

// Only process successful payments
if ($paymentStatus !== 'success') {
    writeLog('received', "Ignored: Payment not successful (status: $paymentStatus)");
    http_response_code(200);
    exit("Payment not successful");
}

// ------------------------- STEP 4: VERIFY WITH PAYCHANGU API -------------------------
$verifyUrl = "https://api.paychangu.com/verify-payment/{$tx_ref}";

writeLog('debug', "Verifying with Paychangu API");

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $verifyUrl,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_HTTPHEADER => [
        "Accept: application/json",
        "Authorization: Bearer " . $paychanguSecretKey
    ],
]);

$verifyResponse = curl_exec($ch);
$verifyHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$verifyError = curl_error($ch);
curl_close($ch);

if ($verifyError || $verifyHttpCode !== 200) {
    writeLog('suspicious', "Verification FAILED: HTTP $verifyHttpCode");
    http_response_code(500);
    exit("Verification failed");
}

$verificationResponse = json_decode($verifyResponse, true);
$verificationData = $verificationResponse['data'] ?? null;

if (!$verificationData || ($verificationData['status'] ?? '') !== 'success') {
    writeLog('suspicious', "Verification returned non-success");
    http_response_code(200);
    exit("Payment verification failed");
}

if (($verificationData['tx_ref'] ?? '') !== $tx_ref) {
    writeLog('suspicious', "TX_REF MISMATCH!");
    http_response_code(200);
    exit("Transaction reference mismatch");
}

writeLog('received', "✓ Payment VERIFIED - Amount: {$verificationData['amount']}, Currency: {$verificationData['currency']}");

// ------------------------- STEP 5: FORWARD VIA GET PARAMETERS (BYPASS JS CHALLENGE) -------------------------

// Prepare the payload
$forwardPayload = [
    'tx_ref' => $tx_ref,
    'verification_data' => $verificationData,
    'timestamp' => time()
];

$payloadJson = json_encode($forwardPayload);
$forwardSignature = hash_hmac('sha256', $payloadJson, $handlerSecret);

// Encode payload as base64 for GET parameter
$encodedPayload = base64_encode($payloadJson);

// Build URL with GET parameters
$urlWithParams = $handlerUrl . '?' . http_build_query([
    'payload' => $encodedPayload,
    'signature' => $forwardSignature
]);

writeLog('debug', "Forwarding to InfinityFree via GET parameters");
writeLog('debug', "URL length: " . strlen($urlWithParams) . " bytes");

// Make GET request (bypasses JavaScript challenge)
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $urlWithParams,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 30,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_HTTPHEADER => [
        "User-Agent: PaychanguWebhook/2.0"
    ]
]);

$handlerResponse = curl_exec($ch);
$handlerHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$handlerError = curl_error($ch);
$effectiveUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
curl_close($ch);

writeLog('debug', "Handler response: HTTP $handlerHttpCode");

if ($handlerError) {
    writeLog('suspicious', "Handler connection ERROR: $handlerError");
    http_response_code(500);
    exit("Handler connection failed");
}

// Check if we got a JSON response (success) or HTML (still blocked)
$responseData = json_decode($handlerResponse, true);

if ($responseData === null && strpos($handlerResponse, '<html>') !== false) {
    writeLog('suspicious', "Handler still returned HTML/JavaScript challenge");
    writeLog('debug', "Response preview: " . substr($handlerResponse, 0, 500));
    http_response_code(500);
    exit("Handler returned JavaScript challenge - GET parameter approach failed");
}

if ($handlerHttpCode !== 200) {
    writeLog('suspicious', "Handler returned HTTP $handlerHttpCode");
    http_response_code(500);
    exit("Handler processing failed");
}

// Check if handler actually processed the payment
if ($responseData && isset($responseData['success']) && $responseData['success']) {
    writeLog('received', "✓✓✓ SUCCESS - Handler processed payment for $tx_ref");
    writeLog('received', "Handler data: " . json_encode($responseData['data'] ?? []));
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'message' => 'Payment processed successfully',
        'tx_ref' => $tx_ref,
        'handler_response' => $responseData
    ]);
    exit;
} else {
    writeLog('suspicious', "Handler returned non-success response: $handlerResponse");
    http_response_code(500);
    exit("Handler processing failed");
}
