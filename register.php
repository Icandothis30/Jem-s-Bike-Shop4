<?php
// login.php file

// Establish database connection
$servername = "localhost";
$username = "root";
$password = ""; 
$dbname = "jems'_bike_shop"; // Make sure to set your actual database name

$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Collect login data
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username']; // This is the email
    $password = $_POST['password'];

    // Use prepared statement to prevent SQL injection
    $stmt = $conn->prepare("SELECT password FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        // Fetch the hash from the database
        $stmt->bind_result($hashedPassword);
        $stmt->fetch();

        // Verify password
        if (password_verify($password, $hashedPassword)) {
            echo "Login successful!";
            // Redirect to a welcome page or dashboard
            // header("Location: welcome.php");
        } else {
            echo "Invalid password!";
        }
    } else {
        echo "Username not found!";
    }

    $stmt->close();
}

$conn->close();
?>
