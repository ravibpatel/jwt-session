<?php
require_once __DIR__ . "/session.php";

$_SESSION["id"] = 520;
$_SESSION["email"] = "example@example.com";
$_SESSION["name"] = "Jessica";

echo "<p>Logged In! Click <a href='index.php'>here</a> to return to home page.</p>";