<?php
declare(strict_types=1);

// Enable error reporting for debugging (remove in production)
error_reporting(E_ALL);
ini_set('display_errors', '1');

date_default_timezone_set('Africa/Blantyre');

// ------------------------- CONFIG -------------------------
// Read from Railway environment variables
$paychanguSecretKey = getenv('secretkey');
$webhookSecret = getenv('WEBHOOK_SECRET') ?: 'X7f8a9c2b3e1f4567890abcdef123456';

// Debug: Check if environment variable is loaded (REMOVE THIS AFTER DEBUGGING)
if (!$paychanguSecretKey) {
    http_response_code(500);
    echo "Configuration error: secretkey not found in environment variables\n";
    echo "Available env vars: " . implode(', ', array_keys($_ENV)) . "\n";
    exit;
}

// ------------------------- PATHS -------------------------
$logDir = __DIR__ . '/logs';
$receivedLog = $logDir . '/webhook_received.log';
$suspiciousLog = $logDir . '/webhook_suspicious.log';
$debugLog = $logDir . '/webhook_debug.log';

// Ensure logs directory exists with proper permissions
if (!is_dir($logDir)) {
    if (!@mkdir($logDir, 0755, true)) {
        error_log("Failed to create logs directory at: $logDir");
    }
}

// ------------------------- HELPER FUNCTIONS -------------------------

// InfinityFree-compatible getallheaders() replacement
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

// Case-insensitive header retrieval
function getHeader($headers, $name) {
    foreach ($headers as $key => $value) {
        if (strcasecmp($key, $name) === 0) {
            return $value;
        }
    }
    return null;
}

// Safe logging function
function safeLog($file, $message) {
    @file_put_contents($file, date('Y-m-d H:i:s') . " - " . $message . PHP_EOL, FILE_APPEND);
}

// ------------------------- RECEIVE PAYLOAD -------------------------
$payload = file_get_contents('php://input');
$headers = getallheaders();

// Debug log - helps diagnose issues
safeLog($debugLog, "Headers received: " . json_encode($headers));
safeLog($debugLog, "Payload: " . $payload);

// ------------------------- VALIDATE SIGNATURE -------------------------

// Try multiple methods to get the signature (InfinityFree compatibility)
$signature = getHeader($headers, 'Signature');
if (!$signature) {
    $signature = $_SERVER['HTTP_SIGNATURE'] ?? null;
}

if (!$signature) {
    http_response_code(400);
    safeLog($suspiciousLog, "Missing Signature header. Headers: " . json_encode($headers));
    exit("Missing Signature header");
}

$computedSignature = hash_hmac('sha256', $payload, $webhookSecret);

if (!hash_equals($computedSignature, $signature)) {
    http_response_code(403);
    safeLog($suspiciousLog, "Invalid signature. Expected: $computedSignature, Got: $signature, Payload: $payload");
    exit("Invalid signature");
}

// ------------------------- PARSE PAYLOAD -------------------------
$data = json_decode($payload, true);
if (!$data) {
    http_response_code(400);
    safeLog($suspiciousLog, "Invalid JSON payload: $payload");
    exit("Invalid payload");
}

// ------------------------- LOG WEBHOOK -------------------------
safeLog($receivedLog, "Valid webhook received: " . $payload);

// ------------------------- VERIFY TRANSACTION WITH PAYCHANGU -------------------------
if (!isset($data['tx_ref'])) {
    http_response_code(400);
    safeLog($suspiciousLog, "Missing tx_ref in payload: $payload");
    exit("Missing tx_ref");
}

$tx_ref = $data['tx_ref'];

$curl = curl_init();
curl_setopt_array($curl, [
    CURLOPT_URL => "https://api.paychangu.com/verify-payment/" . $tx_ref,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
    CURLOPT_TIMEOUT => 30,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_HTTPHEADER => [
        "accept: application/json",
        "Authorization: Bearer " . $paychanguSecretKey
    ],
]);

$response = curl_exec($curl);
$httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
$err = curl_error($curl);
curl_close($curl);

if ($err) {
    safeLog($suspiciousLog, "cURL error for tx_ref $tx_ref: $err");
    http_response_code(500);
    exit("Transaction verification failed");
}

if ($httpCode !== 200) {
    safeLog($suspiciousLog, "HTTP $httpCode error for tx_ref $tx_ref: $response");
    http_response_code(500);
    exit("Transaction verification failed");
}

$verification = json_decode($response, true);

if (!$verification || $verification['status'] !== 'success' || $verification['data']['status'] !== 'success') {
    safeLog($suspiciousLog, "Transaction not successful for tx_ref $tx_ref: $response");
    http_response_code(200); // Return 200 so PayChangu stops retrying
    exit("Transaction not successful");
}

// ------------------------- SUCCESSFUL PAYMENT -------------------------
safeLog($receivedLog, "Payment verified successfully for tx_ref $tx_ref: $response");

// TODO: Add your business logic here
// - Update database
// - Send confirmation email
// - Trigger fulfillment process

// ------------------------- RESPONSE -------------------------
http_response_code(200);
echo "Webhook received and transaction verified successfully";
exit;
