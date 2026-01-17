<?php
// ============================================================================
// webhook.php - DEPLOY ON RAILWAY
// Receives PayChangu webhooks, verifies them, stores for InfinityFree pickup
// ============================================================================
declare(strict_types=1);
date_default_timezone_set('Africa/Blantyre');

// ------------------------- CONFIG -------------------------
$webhookSecret = getenv('WEBHOOK_SECRET');
$paychanguSecretKey = getenv('PAYCHANGU_SECRET_KEY');
$sharedSecret = getenv('SHARED_SECRET');

// ------------------------- PATHS -------------------------
$logDir = __DIR__ . '/logs';
$pendingDir = __DIR__ . '/pending';
$receivedLog = $logDir . '/webhook_received.log';
$suspiciousLog = $logDir . '/webhook_suspicious.log';
$debugLog = $logDir . '/webhook_debug.log';

if (!is_dir($logDir)) @mkdir($logDir, 0755, true);
if (!is_dir($pendingDir)) @mkdir($pendingDir, 0755, true);

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

// ------------------------- HANDLE DIFFERENT REQUESTS -------------------------
$action = $_GET['action'] ?? 'webhook';

// ACTION 1: Receive webhook from PayChangu
if ($action === 'webhook') {
    
    $payload = file_get_contents('php://input');
    $headers = getallheaders();
    
    safeLog($debugLog, "Headers received: " . json_encode($headers));
    safeLog($debugLog, "Payload: " . $payload);
    
    // Validate signature
    $signature = getHeader($headers, 'Signature');
    if (!$signature) {
        $signature = $_SERVER['HTTP_SIGNATURE'] ?? null;
    }
    
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
    
    $data = json_decode($payload, true);
    if (!$data) {
        http_response_code(400);
        safeLog($suspiciousLog, "Invalid JSON payload: $payload");
        exit("Invalid payload");
    }
    
    safeLog($receivedLog, "Valid webhook received: " . $payload);
    
    // Verify with PayChangu
    if (!isset($data['tx_ref'])) {
        http_response_code(400);
        safeLog($suspiciousLog, "Missing tx_ref in payload");
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
        http_response_code(200);
        exit("Transaction not successful");
    }
    
    safeLog($receivedLog, "Payment verified successfully for tx_ref $tx_ref");
    
    // Store verified payment for InfinityFree to pick up
    $filename = $pendingDir . '/' . $tx_ref . '.json';
    file_put_contents($filename, json_encode($verification['data'], JSON_PRETTY_PRINT));
    
    safeLog($receivedLog, "Stored verified payment: $filename");
    
    http_response_code(200);
    exit("Webhook received and transaction verified successfully");
}

// ACTION 2: InfinityFree fetches pending payments
elseif ($action === 'get_pending') {
    
    // Simple authentication
    $token = $_GET['token'] ?? '';
    $expectedToken = hash_hmac('sha256', date('Y-m-d'), $sharedSecret);
    
    if (!hash_equals($expectedToken, $token)) {
        http_response_code(403);
        exit(json_encode(['error' => 'Unauthorized']));
    }
    
    // Get all pending payment files
    $files = glob($pendingDir . '/*.json');
    $pending = [];
    
    foreach ($files as $file) {
        $data = json_decode(file_get_contents($file), true);
        if ($data) {
            $pending[] = [
                'tx_ref' => $data['tx_ref'],
                'data' => $data
            ];
        }
    }
    
    header('Content-Type: application/json');
    echo json_encode(['payments' => $pending]);
    safeLog($receivedLog, "Sent " . count($pending) . " pending payments to InfinityFree");
    exit;
}

// ACTION 3: InfinityFree marks payment as processed
elseif ($action === 'mark_done') {
    
    $token = $_POST['token'] ?? '';
    $expectedToken = hash_hmac('sha256', date('Y-m-d'), $sharedSecret);
    
    if (!hash_equals($expectedToken, $token)) {
        http_response_code(403);
        exit(json_encode(['error' => 'Unauthorized']));
    }
    
    $tx_ref = $_POST['tx_ref'] ?? '';
    if (!$tx_ref) {
        http_response_code(400);
        exit(json_encode(['error' => 'Missing tx_ref']));
    }
    
    $filename = $pendingDir . '/' . $tx_ref . '.json';
    
    if (file_exists($filename)) {
        unlink($filename);
        safeLog($receivedLog, "Marked as processed: $tx_ref");
        echo json_encode(['success' => true]);
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'Not found']);
    }
    exit;
}

else {
    http_response_code(404);
    exit("Unknown action");
}
