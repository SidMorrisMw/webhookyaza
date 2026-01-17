// ============================================================================
// FILE 1: webhook.php - DEPLOY THIS FILE ON RAILWAY
// ============================================================================
<?php
declare(strict_types=1);
date_default_timezone_set('Africa/Blantyre');

// ------------------------- CONFIG -------------------------
$webhookSecret = getenv('WEBHOOK_SECRET'); // From PayChangu dashboard
$paychanguSecretKey = getenv('PAYCHANGU_SECRET_KEY'); // Your PayChangu API key
$sharedSecret = getenv('SHARED_SECRET'); // Generate: openssl rand -hex 32

// ------------------------- SETUP DIRECTORIES -------------------------
$logDir = __DIR__ . '/logs';
$pendingDir = __DIR__ . '/pending';
$processedDir = __DIR__ . '/processed';

foreach ([$logDir, $pendingDir, $processedDir] as $dir) {
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
}

// ------------------------- HELPER FUNCTIONS -------------------------
function logMsg($msg, $level = 'INFO') {
    global $logDir;
    $file = $logDir . '/webhook_' . date('Y-m-d') . '.log';
    $line = date('H:i:s') . " [$level] $msg\n";
    @file_put_contents($file, $line, FILE_APPEND);
}

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
        if (strcasecmp($key, $name) === 0) return $value;
    }
    return null;
}

// ------------------------- HANDLE DIFFERENT ENDPOINTS -------------------------
$action = $_GET['action'] ?? 'webhook';

// ENDPOINT 1: Receive PayChangu webhook
if ($action === 'webhook') {
    
    $payload = file_get_contents('php://input');
    $headers = getallheaders();
    
    // Validate signature
    $signature = getHeader($headers, 'Signature') ?? $_SERVER['HTTP_SIGNATURE'] ?? null;
    
    if (!$signature) {
        http_response_code(400);
        logMsg("Missing signature", 'ERROR');
        exit('Missing signature');
    }
    
    $computedSig = hash_hmac('sha256', $payload, $webhookSecret);
    
    if (!hash_equals($computedSig, $signature)) {
        http_response_code(403);
        logMsg("Invalid signature", 'ERROR');
        exit('Invalid signature');
    }
    
    $data = json_decode($payload, true);
    
    if (!$data || !isset($data['tx_ref'])) {
        http_response_code(400);
        logMsg("Invalid payload", 'ERROR');
        exit('Invalid payload');
    }
    
    $txRef = $data['tx_ref'];
    $status = $data['status'] ?? '';
    
    logMsg("Webhook received: $txRef (status: $status)");
    
    // Only process successful payments
    if ($status !== 'success') {
        logMsg("Ignoring non-success payment: $txRef");
        http_response_code(200);
        exit('Not successful');
    }
    
    // Verify with PayChangu API
    $ch = curl_init("https://api.paychangu.com/verify-payment/{$txRef}");
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            "Accept: application/json",
            "Authorization: Bearer {$paychanguSecretKey}"
        ],
        CURLOPT_TIMEOUT => 30
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        http_response_code(500);
        logMsg("Verification failed for $txRef: HTTP $httpCode", 'ERROR');
        exit('Verification failed');
    }
    
    $verified = json_decode($response, true);
    
    if (!$verified || $verified['status'] !== 'success' || $verified['data']['status'] !== 'success') {
        http_response_code(400);
        logMsg("Verification unsuccessful for $txRef", 'ERROR');
        exit('Verification unsuccessful');
    }
    
    logMsg("✓ Verified: $txRef");
    
    // Store verified payment
    $paymentData = [
        'tx_ref' => $txRef,
        'verification_data' => $verified['data'],
        'verified_at' => time(),
        'processed' => false
    ];
    
    $filename = $pendingDir . '/' . $txRef . '.json';
    file_put_contents($filename, json_encode($paymentData, JSON_PRETTY_PRINT));
    
    logMsg("✓ Stored: $txRef");
    
    http_response_code(200);
    exit('Webhook processed');
}

// ENDPOINT 2: InfinityFree polls for pending payments
elseif ($action === 'get_pending') {
    
    // Authenticate request
    $authToken = $_GET['token'] ?? '';
    $expectedToken = hash_hmac('sha256', date('Y-m-d-H'), $sharedSecret);
    
    if (!hash_equals($expectedToken, $authToken)) {
        http_response_code(403);
        logMsg("Invalid auth token", 'ERROR');
        exit(json_encode(['error' => 'Unauthorized']));
    }
    
    // Get pending payments
    $pending = [];
    $files = glob($pendingDir . '/*.json');
    
    foreach ($files as $file) {
        $data = json_decode(file_get_contents($file), true);
        if ($data && !$data['processed']) {
            $pending[] = [
                'tx_ref' => $data['tx_ref'],
                'data' => $data['verification_data'],
                'verified_at' => $data['verified_at']
            ];
        }
    }
    
    header('Content-Type: application/json');
    echo json_encode(['payments' => $pending, 'count' => count($pending)]);
    logMsg("Sent " . count($pending) . " pending payment(s)");
    exit;
}

// ENDPOINT 3: Mark payment as processed
elseif ($action === 'mark_processed') {
    
    $authToken = $_POST['token'] ?? '';
    $expectedToken = hash_hmac('sha256', date('Y-m-d-H'), $sharedSecret);
    
    if (!hash_equals($expectedToken, $authToken)) {
        http_response_code(403);
        exit(json_encode(['error' => 'Unauthorized']));
    }
    
    $txRef = $_POST['tx_ref'] ?? '';
    
    if (!$txRef) {
        http_response_code(400);
        exit(json_encode(['error' => 'Missing tx_ref']));
    }
    
    $pendingFile = $pendingDir . '/' . $txRef . '.json';
    $processedFile = $processedDir . '/' . $txRef . '.json';
    
    if (file_exists($pendingFile)) {
        $data = json_decode(file_get_contents($pendingFile), true);
        $data['processed'] = true;
        $data['processed_at'] = time();
        
        file_put_contents($processedFile, json_encode($data, JSON_PRETTY_PRINT));
        unlink($pendingFile);
        
        logMsg("✓ Marked processed: $txRef");
        
        header('Content-Type: application/json');
        echo json_encode(['success' => true]);
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'Payment not found']);
    }
    exit;
}

else {
    http_response_code(404);
    exit('Unknown action');
}
