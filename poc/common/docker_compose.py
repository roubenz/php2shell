#!/usr/bin/env python3
"""Tiny `docker compose` subprocess wrappers (project plumbing, stdlib only).

    docker_cp(src, dst)        -> docker compose cp src dst
    compose_restart(service)        -> docker compose restart service  (+ 2s settle)
"""

import subprocess
import time


def docker_cp(src, dst):
    subprocess.run(["docker", "compose", "cp", src, dst],
                   capture_output=True)


def compose_restart(service):
    subprocess.run(["docker", "compose", "restart", service],
                   capture_output=True)
    time.sleep(2)
