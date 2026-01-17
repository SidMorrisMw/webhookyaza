<?php
// ============================================================================
// test_webhook.php - Upload to Railway to test webhook functionality
// Visit: https://your-railway-app.up.railway.app/test_webhook.php
// ============================================================================

echo "<h1>Railway Webhook Test</h1>";
echo "<style>body{font-family:sans-serif;padding:20px;} .success{color:green;} .error{color:red;} .info{color:blue;} pre{background:#f4f4f4;padding:10px;}</style>";

// ============================================
// 1. CHECK ENVIRONMENT VARIABLES
// ============================================
echo "<h2>1. Environment Variables</h2>";
$webhookSecret = getenv('WEBHOOK_SECRET');
$paychanguKey = getenv('PAYCHANGU_SECRET_KEY');
$sharedSecret = getenv('SHARED_SECRET');

echo "WEBHOOK_SECRET: " . ($webhookSecret ? "<span class='success'>✓ SET</span>" : "<span class='error'>✗ NOT SET</span>") . "<br>";
echo "PAYCHANGU_SECRET_KEY: " . ($paychanguKey ? "<span class='success'>✓ SET</span>" : "<span class='error'>✗ NOT SET</span>") . "<br>";
echo "SHARED_SECRET: " . ($sharedSecret ? "<span class='success'>✓ SET</span>" : "<span class='error'>✗ NOT SET</span>") . "<br>";

// ============================================
// 2. CHECK DIRECTORIES
// ============================================
echo "<h2>2. Directory Permissions</h2>";
$logDir = __DIR__ . '/logs';
$pendingDir = __DIR__ . '/pending';

foreach ([$logDir, $pendingDir] as $dir) {
    if (!is_dir($dir)) {
        $created = @mkdir($dir, 0755, true);
        echo basename($dir) . ": " . ($created ? "<span class='success'>✓ Created</span>" : "<span class='error'>✗ Failed to create</span>") . "<br>";
    } else {
        $writable = is_writable($dir);
        echo basename($dir) . ": <span class='success'>✓ Exists</span> | Writable: " . ($writable ? "<span class='success'>✓</span>" : "<span class='error'>✗</span>") . "<br>";
    }
}

// ============================================
// 3. TEST FILE WRITE
// ============================================
echo "<h2>3. File Write Test</h2>";
$testFile = $logDir . '/test_' . time() . '.txt';
$writeResult = @file_put_contents($testFile, "Test at " . date('Y-m-d H:i:s'));
if ($writeResult) {
    echo "<span class='success'>✓ Can write to logs directory</span><br>";
    $readContent = file_get_contents($testFile);
    echo "Read back: " . htmlspecialchars($readContent) . "<br>";
    unlink($testFile);
} else {
    echo "<span class='error'>✗ Cannot write to logs directory</span><br>";
}

// ============================================
// 4. TEST PAYCHANGU API CONNECTION
// ============================================
echo "<h2>4. PayChangu API Connection</h2>";
if ($paychanguKey) {
    $ch = curl_init('https://api.paychangu.com');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => ["Authorization: Bearer " . $paychanguKey]
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        echo "<span class='error'>✗ CURL Error: " . htmlspecialchars($error) . "</span><br>";
    } else {
        echo "<span class='success'>✓ API Reachable (HTTP $httpCode)</span><br>";
    }
} else {
    echo "<span class='error'>✗ Cannot test - PAYCHANGU_SECRET_KEY not set</span><br>";
}

// ============================================
// 5. SIMULATE WEBHOOK RECEPTION
// ============================================
echo "<h2>5. Webhook Simulation</h2>";
if ($webhookSecret) {
    $fakePayload = json_encode([
        'tx_ref' => 'TEST_' . time(),
        'status' => 'success',
        'amount' => 1000,
        'currency' => 'MWK'
    ]);
    
    $fakeSignature = hash_hmac('sha256', $fakePayload, $webhookSecret);
    
    echo "<pre>Payload: " . htmlspecialchars($fakePayload) . "</pre>";
    echo "<pre>Computed Signature: " . $fakeSignature . "</pre>";
    echo "<p class='info'>Copy this signature and use it to test webhook.php with curl:</p>";
    echo "<pre style='background:#000;color:#0f0;padding:15px;'>";
    echo "curl -X POST https://your-railway-url.up.railway.app/webhook.php?action=webhook \\\n";
    echo "  -H 'Content-Type: application/json' \\\n";
    echo "  -H 'Signature: $fakeSignature' \\\n";
    echo "  -d '$fakePayload'";
    echo "</pre>";
} else {
    echo "<span class='error'>✗ Cannot simulate - WEBHOOK_SECRET not set</span><br>";
}

// ============================================
// 6. TEST GET_PENDING ENDPOINT
// ============================================
echo "<h2>6. Test get_pending Endpoint</h2>";
if ($sharedSecret) {
    $token = hash_hmac('sha256', date('Y-m-d'), $sharedSecret);
    $testUrl = "https://" . $_SERVER['HTTP_HOST'] . "/webhook.php?action=get_pending&token=" . urlencode($token);
    
    echo "<p>Test URL (click to test):</p>";
    echo "<a href='$testUrl' target='_blank' style='color:blue;'>$testUrl</a><br><br>";
    
    echo "<p class='info'>Expected: JSON response with 'payments' array</p>";
} else {
    echo "<span class='error'>✗ Cannot test - SHARED_SECRET not set</span><br>";
}

// ============================================
// 7. CHECK LOGS
// ============================================
echo "<h2>7. Recent Logs</h2>";
$logFiles = glob($logDir . '/*.log');
if (empty($logFiles)) {
    echo "<p class='info'>No logs yet</p>";
} else {
    foreach (array_slice($logFiles, -3) as $logFile) {
        echo "<h3>" . basename($logFile) . "</h3>";
        $lines = file($logFile);
        $recentLines = array_slice($lines, -10);
        echo "<pre>" . htmlspecialchars(implode('', $recentLines)) . "</pre>";
    }
}

// ============================================
// 8. CHECK PENDING PAYMENTS
// ============================================
echo "<h2>8. Pending Payments</h2>";
$pendingFiles = glob($pendingDir . '/*.json');
if (empty($pendingFiles)) {
    echo "<p class='info'>No pending payments</p>";
} else {
    echo "<p>Found " . count($pendingFiles) . " pending payment(s):</p>";
    foreach ($pendingFiles as $file) {
        echo "<h3>" . basename($file) . "</h3>";
        $content = file_get_contents($file);
        echo "<pre>" . htmlspecialchars($content) . "</pre>";
    }
}

echo "<hr>";
echo "<h2>Summary</h2>";
echo "<p>If all checks show ✓, your Railway webhook is ready!</p>";
echo "<p><strong>Next step:</strong> Test with a real PayChangu webhook or use the curl command above.</p>";
