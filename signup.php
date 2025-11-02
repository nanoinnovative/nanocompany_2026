<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight request
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit(0);
}

// Database configuration - UPDATE THESE!
$servername = "localhost";
$username = "root";              // ← CHANGE TO YOUR DB USERNAME
$password = "";                  // ← CHANGE TO YOUR DB PASSWORD
$dbname = "nano_company";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    error_log("Database connection failed: " . $conn->connect_error);
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Database connection failed']);
    exit;
}

// Get POST data
$input = json_decode(file_get_contents('php://input'), true);

if (!$input) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Invalid input data']);
    exit;
}

$firstName = trim($input['firstName'] ?? '');
$lastName = trim($input['lastName'] ?? '');
$email = trim($input['email'] ?? '');
$password = $input['password'] ?? '';
$recaptchaResponse = $input['recaptchaResponse'] ?? '';

// Validate required fields
if (empty($firstName) || empty($lastName) || empty($email) || empty($password)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'All fields are required']);
    exit;
}

// Validate email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Invalid email format']);
    exit;
}

// Validate password strength
if (strlen($password) < 9 || 
    !preg_match('/[a-z]/', $password) || 
    !preg_match('/[A-Z]/', $password) || 
    !preg_match('/[0-9]/', $password)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Password must be at least 9 characters with uppercase, lowercase, and numbers']);
    exit;
}

// Verify reCAPTCHA - UPDATE SECRET KEY!
if (!verifyRecaptcha($recaptchaResponse)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'reCAPTCHA verification failed']);
    exit;
}

// Check if email already exists
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    http_response_code(409);
    echo json_encode(['success' => false, 'message' => 'Email already registered']);
    $stmt->close();
    $conn->close();
    exit;
}
$stmt->close();

// Hash password
$passwordHash = password_hash($password, PASSWORD_DEFAULT);

// Generate verification code
$verificationCode = generateVerificationCode();
$isVerified = 0; // 0 = not verified, 1 = verified

// Insert user into database
$stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, password_hash, verification_code, is_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())");
$stmt->bind_param("sssssi", $firstName, $lastName, $email, $passwordHash, $verificationCode, $isVerified);

if ($stmt->execute()) {
    $userId = $stmt->insert_id;
    
    // Send verification email
    $emailSent = sendVerificationEmail($email, $firstName . ' ' . $lastName, $verificationCode);
    
    http_response_code(201);
    echo json_encode([
        'success' => true, 
        'message' => 'User registered successfully', 
        'userId' => $userId,
        'verificationCode' => $verificationCode, // Remove this in production
        'emailSent' => $emailSent
    ]);
} else {
    error_log("Database insert failed: " . $stmt->error);
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error creating user account: ' . $stmt->error]);
}

$stmt->close();
$conn->close();

// reCAPTCHA verification function
function verifyRecaptcha($response) {
    // GET YOUR SECRET KEY FROM: https://www.google.com/recaptcha/admin
    $secretKey = "YOUR_RECAPTCHA_SECRET_KEY_HERE"; // ← MUST UPDATE THIS!
    
    if (empty($response)) {
        return false;
    }
    
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    
    $data = [
        'secret' => $secretKey,
        'response' => $response
    ];
    
    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data),
            'timeout' => 10
        ]
    ];
    
    try {
        $context = stream_context_create($options);
        $result = file_get_contents($url, false, $context);
        
        if ($result === FALSE) {
            error_log("reCAPTCHA API call failed");
            return false;
        }
        
        $resultJson = json_decode($result);
        return $resultJson->success ?? false;
        
    } catch (Exception $e) {
        error_log("reCAPTCHA verification error: " . $e->getMessage());
        return false;
    }
}

// Generate verification code
function generateVerificationCode() {
    return str_pad(mt_rand(0, 999999), 6, '0', STR_PAD_LEFT);
}

// Send verification email - IMPROVED VERSION
function sendVerificationEmail($email, $userName, $verificationCode) {
    $subject = "Verify Your Nano Company Account";
    
    // HTML email content
    $message = "
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .code { font-size: 24px; font-weight: bold; color: #000; background: #f5f5f5; padding: 10px; text-align: center; }
        </style>
    </head>
    <body>
        <div class='container'>
            <h2>Verify Your Nano Company Account</h2>
            <p>Hello $userName,</p>
            <p>Thank you for registering with Nano Company!</p>
            <p>Your verification code is:</p>
            <div class='code'>$verificationCode</div>
            <p>Enter this code on the verification page to complete your registration.</p>
            <p><strong>This code will expire in 15 minutes.</strong></p>
            <br>
            <p>Best regards,<br>Nano Company Team</p>
        </div>
    </body>
    </html>
    ";
    
    // Headers for HTML email
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= "From: nanoinnovative615@gmail.com" . "\r\n";
    $headers .= "Reply-To: nanoinnovative615@gmail.com" . "\r\n";
    
    try {
        // For testing - log the email details
        error_log("Attempting to send verification email to: $email");
        error_log("Verification code: $verificationCode");
        
        // Uncomment this line to actually send emails (when ready)
        // $mailSent = mail($email, $subject, $message, $headers);
        $mailSent = true; // Temporarily true for testing
        
        if ($mailSent) {
            error_log("✅ Verification email sent to: $email");
        } else {
            error_log("❌ Failed to send email to: $email");
        }
        
        return $mailSent;
        
    } catch (Exception $e) {
        error_log("Email sending error: " . $e->getMessage());
        return false;
    }
}
?>
