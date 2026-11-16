<?php
// Worker-identity probe for the pin verification: echoes the prefork child's
// PID so a client can see whether its requests landed on one child (pinned) or
// scattered across several (unpinned). Pool lab only - not copied into the
// other labs (see lab/apache-pool/Dockerfile).
echo getmypid();
