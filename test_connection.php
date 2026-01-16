<?php
// ============================================================================
// test_connection.php - Run this on RAILWAY to test InfinityFree handler
// Access via browser: https://your-railway-app.com/test_connection.php
// ============================================================================

$handlerUrl = getenv('HANDLER_URL');
$handlerSecret = getenv('HANDLER_SECRET');

?>
<!DOCTYPE html>
<html>
<head>
    <title>Railway → InfinityFree Connection Test</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .success { color: green; font-weight: bold; }
        .error { color: red; font-weight: bold; }
        .info { color: blue; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; border-left: 4px solid #333; }
        .test-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        h2 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
        .step { background: #e3f2fd; padding: 10px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>

<div class="container">
<h1>🚂 Railway → 🌐 InfinityFree Connection Test</h1>
<p class="info">Testing connection from Railway to your InfinityFree payment handler</p>
<p class="info">Time: <?php echo date('Y-m-d H:i:s'); ?></p>

<!-- Configuration -->
<div class="test-section">
<h2>Configuration</h2>
<p><strong>Handler URL:</strong> <?php echo htmlspecialchars($handlerUrl); ?></p>
<p><strong>Secret Key:</strong> <?php echo str_repeat('*', strlen($handlerSecret) - 4) . substr($handlerSecret, -4); ?></p>
</div>

<!-- Test 1: Simple GET request -->
<div class="test-section">
<h2>Test 1: Basic Connectivity (GET Request)</h2>
<?php
echo '<div class="step">Testing if URL is reachable...</div>';

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $handlerUrl,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_VERBOSE => false
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error = curl_error($ch);
$connectTime = curl_getinfo($ch, CURLINFO_CONNECT_TIME);
$totalTime = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
curl_close($ch);

if ($error) {
    echo "<p class=\"error\">✗ Connection FAILED: $error</p>";
} else {
    echo "<p class=\"success\">✓ Connection successful!</p>";
    echo "<p class=\"info\">HTTP Status: $httpCode</p>";
    echo "<p class=\"info\">Connect Time: " . round($connectTime * 1000) . "ms</p>";
    echo "<p class=\"info\">Total Time: " . round($totalTime * 1000) . "ms</p>";
    
    if ($httpCode >= 200 && $httpCode < 300) {
        echo "<p class=\"success\">✓ Server responded successfully</p>";
    } else {
        echo "<p class=\"error\">✗ Server returned error status</p>";
    }
    
    if (!empty($response)) {
        echo "<p class=\"info\">Response preview:</p>";
        echo "<pre>" . htmlspecialchars(substr($response, 0, 500)) . "</pre>";
    }
}
?>
</div>

<!-- Test 2: POST request with signature -->
<div class="test-section">
<h2>Test 2: POST Request with Valid Signature</h2>
<?php
echo '<div class="step">Sending test payment data...</div>';

$testPayload = [
    'tx_ref' => 'TEST_' . time(),
    'verification_data' => [
        'tx_ref' => 'TEST_' . time(),
        'status' => 'success',
        'amount' => 100,
        'currency' => 'MWK',
        'customer' => [
            'email' => 'test@example.com',
            'first_name' => 'Test',
            'last_name' => 'User'
        ]
    ],
    'timestamp' => time()
];

$jsonPayload = json_encode($testPayload);
$signature = hash_hmac('sha256', $jsonPayload, $handlerSecret);

echo "<p class=\"info\">Test payload:</p>";
echo "<pre>" . htmlspecialchars(json_encode($testPayload, JSON_PRETTY_PRINT)) . "</pre>";
echo "<p class=\"info\">Computed signature: $signature</p>";

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $handlerUrl,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $jsonPayload,
    CURLOPT_TIMEOUT => 30,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_HTTPHEADER => [
        "Content-Type: application/json",
        "X-Webhook-Signature: $signature"
    ],
    CURLOPT_FOLLOWLOCATION => true
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error = curl_error($ch);
$info = curl_getinfo($ch);
curl_close($ch);

if ($error) {
    echo "<p class=\"error\">✗ Request FAILED: $error</p>";
} else {
    echo "<p class=\"success\">✓ Request sent successfully!</p>";
    echo "<p class=\"info\">HTTP Status: $httpCode</p>";
    echo "<p class=\"info\">Total Time: " . round($info['total_time'] * 1000) . "ms</p>";
    
    if ($httpCode === 200) {
        echo "<p class=\"success\">✓✓✓ Handler responded with SUCCESS!</p>";
    } elseif ($httpCode === 404) {
        echo "<p class=\"error\">✗ Handler returned 404 - Transaction not found in database (expected for test data)</p>";
    } elseif ($httpCode === 401 || $httpCode === 403) {
        echo "<p class=\"error\">✗ Authentication failed - Check HANDLER_SECRET matches on both sides</p>";
    } else {
        echo "<p class=\"error\">✗ Handler returned error status: $httpCode</p>";
    }
    
    if (!empty($response)) {
        echo "<p class=\"info\">Handler response:</p>";
        echo "<pre>" . htmlspecialchars($response) . "</pre>";
        
        $jsonResponse = json_decode($response, true);
        if ($jsonResponse) {
            echo "<p class=\"info\">Parsed response:</p>";
            echo "<pre>" . htmlspecialchars(json_encode($jsonResponse, JSON_PRETTY_PRINT)) . "</pre>";
        }
    }
}
?>
</div>

<!-- Test 3: Invalid signature test -->
<div class="test-section">
<h2>Test 3: POST Request with Invalid Signature (Should Fail)</h2>
<?php
echo '<div class="step">Testing security - sending request with wrong signature...</div>';

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $handlerUrl,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $jsonPayload,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_HTTPHEADER => [
        "Content-Type: application/json",
        "X-Webhook-Signature: invalid_signature_123"
    ]
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode === 401 || $httpCode === 403) {
    echo "<p class=\"success\">✓ Security working correctly! Invalid signature was rejected (HTTP $httpCode)</p>";
} else {
    echo "<p class=\"error\">✗ Security issue! Handler accepted invalid signature (HTTP $httpCode)</p>";
}
?>
</div>

<!-- Summary -->
<div class="test-section">
<h2>📊 Summary</h2>
<?php
echo '<h3>What these tests mean:</h3>';
echo '<ul>';
echo '<li><strong>Test 1 passes:</strong> Railway can reach InfinityFree ✓</li>';
echo '<li><strong>Test 2 returns 404:</strong> Connection works! (404 is expected because test data isn\'t in your database)</li>';
echo '<li><strong>Test 2 returns 200:</strong> Perfect! Handler processed the request ✓✓✓</li>';
echo '<li><strong>Test 2 returns 401/403:</strong> Signature issue - check HANDLER_SECRET matches</li>';
echo '<li><strong>Test 2 fails to connect:</strong> InfinityFree might be blocking Railway IPs</li>';
echo '<li><strong>Test 3 returns 401/403:</strong> Security is working correctly ✓</li>';
echo '</ul>';

echo '<h3>Next Steps:</h3>';
echo '<ol>';
echo '<li>If tests pass, trigger a real Paychangu payment and check Railway logs</li>';
echo '<li>Check InfinityFree handler.log file for processing details</li>';
echo '<li>Monitor Railway webhook logs at: ' . $handlerUrl . '</li>';
echo '</ol>';
?>
</div>

</div>
</body>
</html>
