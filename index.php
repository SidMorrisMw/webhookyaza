<?php
// ============================================================================
// webhook.php - DEPLOY ON RAILWAY (SIMPLIFIED - TRUST SIGNATURE)
// Receives PayChangu webhooks, verifies signature, stores for InfinityFree
// ============================================================================
declare(strict_types=1);
date_default_timezone_set('Africa/Blantyre');

// ------------------------- CONFIG -------------------------
$webhookSecret = getenv('WEBHOOK_SECRET');
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
    
    // Signature is valid - we can trust this webhook
    safeLog($receivedLog, "✓ Valid signature - webhook authenticated");
    
    $data = json_decode($payload, true);
    if (!$data) {
        http_response_code(400);
        safeLog($suspiciousLog, "Invalid JSON payload: $payload");
        exit("Invalid payload");
    }
    
    // Extract tx_ref
    $tx_ref = $data['tx_ref'] ?? null;
    if (!$tx_ref) {
        http_response_code(400);
        safeLog($suspiciousLog, "Missing tx_ref in payload");
        exit("Missing tx_ref");
    }
    
    // Check if payment was successful
    $status = $data['status'] ?? 'unknown';
    
    safeLog($receivedLog, "Payment received - tx_ref: $tx_ref, status: $status");
    
    if ($status === 'success') {
        // Store the payment for InfinityFree to pick up
        $filename = $pendingDir . '/' . $tx_ref . '.json';
        $writeResult = file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT));
        
        if ($writeResult === false) {
            safeLog($suspiciousLog, "Failed to write file: $filename");
            http_response_code(500);
            exit("Failed to store payment");
        }
        
        safeLog($receivedLog, "✓ Payment stored successfully: $filename (bytes: $writeResult)");
        
        http_response_code(200);
        exit("Webhook received and payment stored successfully");
    } else {
        safeLog($receivedLog, "Payment not successful (status: $status) - not storing");
        http_response_code(200);
        exit("Webhook received - payment not successful");
    }
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
                'tx_ref' => $data['tx_ref'] ?? basename($file, '.json'),
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
