<?php
require_once __DIR__ . "/session.php";

if(isset($_SESSION["id"])) {
    echo "<p>Session already started. Content of session variable are as follows.</p>";
    print_r($_SESSION);
    echo "<p>Click <a href='destroy.php'>here</a> to destroy session.";
} else {
    echo "<p>Session not running!. Please login <a href='login.php'>here</a></p>";
}