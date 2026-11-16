<?php
// Minimal real session-using endpoint: session_start() + two scalar $_SESSION entries,
// the shape any ordinary PHP app produces. Stands in for "a real session-using app" so
// the chain's stage decode gets a 2-scalar session over pure HTTP (no docker-exec seed).
session_start();
$_SESSION['a'] = (int)($_GET['a'] ?? 0);
$_SESSION['b'] = (int)($_GET['b'] ?? 0);
echo "S " . session_id() . "\n";
