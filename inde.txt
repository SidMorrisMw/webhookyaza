<?php
// ============================================================================
// index.php (HOSTED ON RAILWAY) - Modified to use GET parameters
// ============================================================================
declare(strict_types=1);

date_default_timezone_set('Africa/Blantyre');

// ------------------------- CONFIG -------------------------
$paychanguSecretKey = getenv('secretkey');
$webhookSecret = getenv('WEBHOOK_SECRET');
$handlerUrl = getenv('HANDLER_URL'); // e.g., https://yazaitmw.great-site.net/payment_handler.php
$handlerSecret = getenv('HANDLER_SECRET'); // Shared secret between webhook and handler

// ------------------------- PATHS -------------------------
$logDir = __DIR__ . '/logs';
$receivedLog = $logDir . '/webhook_received.log';
$suspiciousLog = $logDir . '/webhook_suspicious.log';
$debugLog = $logDir . '/webhook_debug.log';

// Ensure logs directory exists
if (!is_dir($logDir)) {
    @mkdir($logDir, 0755, true);
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

function safeLog($file, $message) {
    @file_put_contents($file, date('Y-m-d H:i:s') . " - " . $message . PHP_EOL, FILE_APPEND);
}

// ------------------------- RECEIVE PAYLOAD -------------------------
$payload = file_get_contents('php://input');
$headers = getallheaders();

safeLog($debugLog, "Headers: " . json_encode($headers));
safeLog($debugLog, "Payload length: " . strlen($payload));

// ------------------------- VALIDATE SIGNATURE -------------------------

$signature = getHeader($headers, 'Signature') ?? $_SERVER['HTTP_SIGNATURE'] ?? null;

if (!$signature) {
    http_response_code(400);
    safeLog($suspiciousLog, "Missing Signature header");
    exit("Missing Signature header");
}

$computedSignature = hash_hmac('sha256', $payload, $webhookSecret);

if (!hash_equals($computedSignature, $signature)) {
    http_response_code(403);
    safeLog($suspiciousLog, "Invalid signature. Expected: $computedSignature, Got: $signature");
    exit("Invalid signature");
}

// ------------------------- PARSE PAYLOAD -------------------------
$data = json_decode($payload, true);
if (!$data || !isset($data['tx_ref'])) {
    http_response_code(400);
    safeLog($suspiciousLog, "Invalid payload: $payload");
    exit("Invalid payload");
}

$tx_ref = $data['tx_ref'];
$paymentStatus = $data['status'] ?? null;

safeLog($receivedLog, "Valid webhook received for tx_ref: $tx_ref, status: $paymentStatus");

// Only process successful payments
if ($paymentStatus !== 'success') {
    safeLog($receivedLog, "Payment not successful for $tx_ref: status = $paymentStatus");
    http_response_code(200); // Acknowledge to stop retries
    exit("Payment not successful");
}

// ------------------------- FORWARD TO HANDLER VIA GET PARAMETERS -------------------------

$handlerPayload = [
    'tx_ref' => $tx_ref,
    'payment_data' => $data,
    'timestamp' => time()
];

$handlerPayloadJson = json_encode($handlerPayload);

// Create HMAC signature for handler authentication
$handlerSignature = hash_hmac('sha256', $handlerPayloadJson, $handlerSecret);

// **KEY CHANGE**: Send via GET parameters instead of POST body
$encodedPayload = base64_encode($handlerPayloadJson);

// Build URL with parameters
$urlWithParams = $handlerUrl . '?' . http_build_query([
    'payload' => $encodedPayload,
    'signature' => $handlerSignature
]);

safeLog($debugLog, "Forwarding to handler via GET parameters");

// Make GET request (bypasses JavaScript challenge)
$handlerCurl = curl_init();
curl_setopt_array($handlerCurl, [
    CURLOPT_URL => $urlWithParams,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 30,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTPHEADER => [
        "User-Agent: PaychanguWebhook/1.0"
    ],
]);

$handlerResponse = curl_exec($handlerCurl);
$handlerHttpCode = curl_getinfo($handlerCurl, CURLINFO_HTTP_CODE);
$handlerError = curl_error($handlerCurl);
curl_close($handlerCurl);

if ($handlerError) {
    safeLog($suspiciousLog, "Handler connection error for $tx_ref: $handlerError");
    http_response_code(500);
    exit("Handler connection failed");
}

// Check if response is HTML (JavaScript challenge)
if (strpos($handlerResponse, '<html>') !== false) {
    safeLog($suspiciousLog, "Handler returned HTML/JS challenge for $tx_ref");
    http_response_code(500);
    exit("Handler blocked by JavaScript challenge");
}

if ($handlerHttpCode !== 200) {
    safeLog($suspiciousLog, "Handler failed for $tx_ref: HTTP $handlerHttpCode, Response: $handlerResponse");
    http_response_code(500);
    exit("Handler processing failed");
}

safeLog($receivedLog, "Handler processed successfully for $tx_ref: $handlerResponse");

http_response_code(200);
echo "Webhook processed successfully";
exit;
