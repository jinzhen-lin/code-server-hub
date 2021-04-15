# encoding: utf-8
import asyncio
import os
import signal
from subprocess import Popen

from jupyterhub.utils import exponential_backoff, wait_for_http_server
from tornado.ioloop import PeriodicCallback
from tornado.log import app_log

from .utils import random_hash_str, random_port, sha256sum


def make_preexec_fn(username):
    import grp
    import pwd

    user = pwd.getpwnam(username)
    uid = user.pw_uid
    gid = user.pw_gid
    gids = [g.gr_gid for g in grp.getgrall() if username in g.gr_mem]

    def preexec():
        os.setgid(gid)
        try:
            os.setgroups(gids)
        except Exception:
            pass
        os.setuid(uid)

    return preexec


class CodeServerSpawner(object):
    """
    A Spawner that uses `subprocess.Popen` to start code-server as local process.
    """

    def __init__(self, username, cmd="code-server"):
        self.cmd = cmd
        self.check_running_pc = None
        self.check_running_interval = 5
        self.username = username
        self.status = "init"
        self.proc = self.password = self.hashed_password = None
        self.pid = self.port = 0

    async def start(self):
        """Start the code-server."""
        if self.status == "ready":
            return True
        elif self.status in ("starting", "pending"):
            # waiting for the server to be ready
            for i in range(10):
                await asyncio.sleep(1)
                if self.status == "ready":
                    # server become ready
                    return True
                elif self.status in ("starting", "pending") and i == 9:
                    # server is still starting or pending
                    return False
                else:
                    # previous starting process is failed
                    break

        self.status = "starting"
        port = random_port()
        proxy_target = f"127.0.0.1:{port}"
        app_log.info(f"Starting code server for '{self.username}' at {proxy_target}")
        cmd = [
            self.cmd, "--bind-addr", proxy_target,
            "--disable-telemetry",
            "--disable-update-check"
        ]
        cmd = ["bash", "-l", "-c", " ".join(cmd)]
        password = random_hash_str()
        try:
            proc = Popen(
                cmd, preexec_fn=make_preexec_fn(self.username),
                start_new_session=True, env={"PASSWORD": password}
            )
        except Exception:
            app_log.warning(f"Cannot start code server for '{self.username}':")
            app_log.exception("")
            self.status = "stopped"
            return False
        self.proc = proc

        if proc.poll() is not None:
            # the code-server process is exited
            app_log.warning(f"Cannot start code server for '{self.username}':")
            return False
        self.status = "started"
        url = f"http://127.0.0.1:{port}/"

        for _ in range(10):
            # check if the web service of code-server is ready
            try:
                await wait_for_http_server(url, 1)
            except Exception:
                continue
            else:
                self.status = "ready"
                break
        if self.status != "ready":
            app_log.warning(f"Code server of '{self.username}' cannot be ready in 10s.")
            await self.stop()
            self.proc = None
            return False

        self.port = port
        self.pid = proc.pid
        self.password = password
        self.hashed_password = sha256sum(password)
        if self.check_running_pc is None or not self.check_running_pc.is_running():
            # check if code-server is running every <check_running_interval> seconds.
            check_running_pc = PeriodicCallback(
                self.check_running,
                1e3 * self.check_running_interval
            )
            self.check_running_pc = check_running_pc
            check_running_pc.start()
        app_log.info(f"Code server of '{self.username}' is ready.")
        return True

    async def stop(self):
        """Stop the code-server process."""
        if self.status not in ("starting", "started", "ready"):
            return True
        if self.proc is None:
            return True

        if self.check_running_pc is not None:
            self.check_running_pc.stop()

        app_log.info(f"Stopping code server for '{self.username}'")
        try:
            os.kill(self.proc.pid, signal.SIGINT)
            is_success = await exponential_backoff(
                lambda: self.proc.poll() is None,
                "Process did not die in 5 seconds.",
                timeout=5
            )
        except Exception:
            is_success = False

        self.status = "stopped"
        self.proc = self.password = self.hashed_password = None
        self.pid = self.port = 0
        app_log.info(f"Code server of '{self.username}' is stopped.")
        return is_success

    async def check_running(self):
        """Check if the code-server process is running"""
        if self.proc.poll() is None:
            return
        # if code-server process is exited,
        # set the state of spawner instance.
        app_log.info(f"Code server of '{self.username}' is found to be down.")
        self.status = "stopped"
        self.proc = self.password = self.hashed_password = None
        self.pid = self.port = 0
        if self.check_running_pc is not None:
            self.check_running_pc.stop()
