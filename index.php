<?php
// ============================================================================
// webhook.php - RAILWAY ONLY (NO DATABASE ACCESS)
// Purpose: Receive Paychangu webhooks, verify them, forward to InfinityFree
// ============================================================================
declare(strict_types=1);

date_default_timezone_set('Africa/Blantyre');

// ------------------------- CONFIG -------------------------
$paychanguSecretKey = getenv('secretkey');           // Your Paychangu secret key
$webhookSecret = getenv('WEBHOOK_SECRET');            // Webhook signature secret from Paychangu
$handlerUrl = getenv('HANDLER_URL');                  // InfinityFree handler URL
$handlerSecret = getenv('HANDLER_SECRET');            // Shared secret with InfinityFree

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

writeLog('debug', "Received webhook - Headers: " . json_encode($headers));
writeLog('debug', "Payload: " . $payload);

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
    writeLog('suspicious', "REJECTED: Invalid signature. Expected: $computedSignature, Got: $signature");
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
// IMPORTANT: Always verify with Paychangu before trusting webhook data
$verifyUrl = "https://api.paychangu.com/verify-payment/{$tx_ref}";

writeLog('debug', "Verifying with Paychangu API: $verifyUrl");

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
    writeLog('suspicious', "Verification FAILED: HTTP $verifyHttpCode, Error: $verifyError");
    http_response_code(500);
    exit("Verification failed");
}

$verificationResponse = json_decode($verifyResponse, true);
$verificationData = $verificationResponse['data'] ?? null;

if (!$verificationData || ($verificationData['status'] ?? '') !== 'success') {
    writeLog('suspicious', "Verification returned non-success: " . json_encode($verificationData));
    http_response_code(200);
    exit("Payment verification failed");
}

// Validate transaction reference matches
if (($verificationData['tx_ref'] ?? '') !== $tx_ref) {
    writeLog('suspicious', "TX_REF MISMATCH! Webhook: $tx_ref, Verified: " . ($verificationData['tx_ref'] ?? 'null'));
    http_response_code(200);
    exit("Transaction reference mismatch");
}

writeLog('received', "✓ Payment VERIFIED with Paychangu - Amount: {$verificationData['amount']}, Currency: {$verificationData['currency']}");

// ------------------------- STEP 5: FORWARD TO INFINITYFREE HANDLER -------------------------

$forwardPayload = [
    'tx_ref' => $tx_ref,
    'verification_data' => $verificationData,  // Full verified payment data
    'timestamp' => time()
];

$forwardSignature = hash_hmac('sha256', json_encode($forwardPayload), $handlerSecret);

writeLog('debug', "Forwarding to InfinityFree: $handlerUrl");

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $handlerUrl,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => json_encode($forwardPayload),
    CURLOPT_TIMEOUT => 30,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_HTTPHEADER => [
        "Content-Type: application/json",
        "X-Webhook-Signature: " . $forwardSignature,
        "User-Agent: PaychanguWebhook/1.0"
    ],
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_SSL_VERIFYPEER => true
]);

$handlerResponse = curl_exec($ch);
$handlerHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$handlerError = curl_error($ch);
$connectTime = curl_getinfo($ch, CURLINFO_CONNECT_TIME);
$totalTime = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
curl_close($ch);

// Log detailed response for debugging
writeLog('debug', "Handler response: HTTP $handlerHttpCode, Connect: {$connectTime}s, Total: {$totalTime}s");
writeLog('debug', "Handler body: $handlerResponse");

if ($handlerError) {
    writeLog('suspicious', "Handler connection ERROR: $handlerError");
    http_response_code(500);
    exit("Handler connection failed: $handlerError");
}

if ($handlerHttpCode !== 200) {
    writeLog('suspicious', "Handler returned HTTP $handlerHttpCode: $handlerResponse");
    http_response_code(500);
    exit("Handler processing failed");
}

writeLog('received', "✓✓✓ SUCCESS - Handler processed payment for $tx_ref");

http_response_code(200);
echo "Webhook processed successfully";
exit;
