<?php
/* Target script for OOM-during-parsing requests. On a vulnerable build the
 * request usually dies during php_hash_environment() (before this runs); the
 * point is what request shutdown does with the half-built state afterwards. */
printf("post=%d files=%d\n", count($_POST), count($_FILES));
