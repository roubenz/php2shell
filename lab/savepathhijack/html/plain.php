<?php
// Bare page: it must NOT session_start() (the progress-record and decode
// shaping requests ride the rfc1867 upload-progress hook, which runs
// pre-RINIT regardless) and it must stay cheap so wait_up() can poll the
// worker between arming rounds.
echo "ok\n";
