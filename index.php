<?php
session_start();

$mysqli = new mysqli($host, $username, $password, $database);
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

if (isset($_GET['username'], $_GET['password'], $_GET['user_token'], $_GET['Login'])) {
    $username = $_GET['username'];
    $password = $_GET['password'];
    $user_token = $_GET['user_token'];

    if (empty($username) || empty($password) || empty($user_token)) {
        die('Invalid input parameters');
    }

    $stmt = $mysqli->prepare("SELECT id, first_name, last_name FROM users WHERE username = ? AND password = ? AND user_token = ?");
    $stmt->bind_param("sss", $username, $password, $user_token);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        echo "User found: " . $user['first_name'] . " " . $user['last_name'];
    } else {
        echo 'Invalid credentials or user not found.';
    }

    $stmt->close();
} else {
    echo 'Missing required parameters.';
}

$mysqli->close();
?>
