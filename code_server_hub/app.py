# encoding: utf-8
import argparse
import asyncio
import os
import re
import signal
import stat
from pathlib import Path

import configargparse
import tornado.httputil
import tornado.web
import tornado.websocket
from simplepam import authenticate
from tornado.ioloop import IOLoop

from .spawner import CodeServerSpawner
from .utils import random_hash_str


class BaseHandler(tornado.web.RequestHandler):

    def get_current_user(self):
        username = self.get_secure_cookie("key")
        if username is not None:
            return username.decode()

    def relative_url(self, path, origin_path=None):
        origin_path = origin_path or self.request.path
        return os.path.relpath(path, os.path.dirname(origin_path))

    def render_template(self, template_name, **kwargs):
        ns = {
            "template_name": template_name,
            "relative_url": self.relative_url,
        }
        ns.update(kwargs)
        relative_url = ns["relative_url"]
        ns["relative_static_url"] = lambda path: relative_url(self.static_url(path))
        return self.render(**ns)


class LoginHandler(BaseHandler):
    """Handle login request."""

    async def get(self):
        if self.current_user:
            try:
                import pwd
                pwd.getpwnam(self.current_user)
            except Exception:
                # if self.current_user is not an valid user
                self.clear_cookie("key")
                return self.render_template("login.html")
            else:
                return self.redirect(f"/")
        return self.render_template("login.html")

    async def post(self):
        username = self.get_argument("username", "")
        password = self.get_argument("password", "")
        if authenticate(username, password):
            # `key` is the cookie name of code-server.
            # We use the same cookie name so that user can exit
            # code-server-hub when he click "logout" on the web page
            # of code-server.
            # The cookie would be overrided
            # when we proxy the request to code-server.
            self.set_secure_cookie("key", username)
            return self.redirect("/")
        return self.render_template("login.html", login_fail=True)


class ErrorHandler(BaseHandler):
    """Handle http error."""

    async def get(self, error_code):
        error_code = error_code or "0"
        try:
            error_code = int(error_code)
        except Exception:
            error_code = 0
        if error_code == 503:
            self.set_status(503)
            return self.render_template("503.html")
        self.set_status(404)
        return self.render_template("404.html")


class CodeServerProxyHandler(tornado.websocket.WebSocketHandler):
    """Proxy the web and websocket request to code-server."""

    def initialize(self, **kwargs):
        super().initialize(**kwargs)
        self.ws = None
        self.closed = True

    def get_current_user(self):
        admin_users = self.settings["admin_users"]
        username = self.get_secure_cookie("key")
        if username is None:
            return
        username = username.decode()
        pattern = re.compile("^/hub/admin/user/([a-zA-Z0-9]+)/")
        if pattern.match(self.request.uri):
            if username not in admin_users:
                return
            # admin users can access code-server of <username>
            # by visit `/hub/admin/user/<username>/``
            username = pattern.findall(self.request.uri)[0]
            self.request.uri = pattern.sub("/", self.request.uri)
        return username

    @tornado.web.authenticated
    async def get(self, *args, **kwargs):
        if self.request.headers.get("Upgrade", "").lower() == "websocket":
            # if this is a websocket request
            return await super().get(*args, **kwargs)
        return await self.web_proxy(*args, **kwargs)

    @tornado.web.authenticated
    async def post(self, *args, **kwargs):
        return await self.web_proxy(*args, **kwargs)

    @tornado.web.authenticated
    async def put(self, *args, **kwargs):
        return await self.web_proxy(*args, **kwargs)

    @tornado.web.authenticated
    async def delete(self, *args, **kwargs):
        return await self.web_proxy(*args, **kwargs)

    async def web_proxy(self, *args, **kwargs):
        """Proxy the request to code-server."""
        username = self.current_user
        spawner = self.settings["spawners"].get(username, None)
        if spawner is None:
            spawner_cmd = self.settings["spawner_cmd"]
            spawner = CodeServerSpawner(username, spawner_cmd)
            self.settings["spawners"][username] = spawner

        if spawner.status != "ready":
            await spawner.start()
        if spawner.status != "ready":
            await spawner.stop()
            return self.redirect("/hub/error/503")

        self.proxy_error = False
        # override the cookie
        headers = self.request.headers.copy()
        headers["cookie"] = "key=" + spawner.hashed_password
        url = f"http://127.0.0.1:{spawner.port}" + self.request.uri
        body_expected = self.request.method in ("POST", "PATCH", "PUT")
        request = tornado.httpclient.HTTPRequest(
            url=url, follow_redirects=False,
            method=self.request.method,
            headers=headers,
            body=self.request.body if body_expected else None,
            header_callback=self._on_headers,
            streaming_callback=self._on_chunk
        )
        client = tornado.httpclient.AsyncHTTPClient()
        await client.fetch(request, raise_error=False)
        if self.proxy_error:
            await spawner.stop()
            self.redirect("/hub/error/503")
        self.finish()

    async def open(self):
        self.closed = False
        username = self.current_user

        spawner = self.settings["spawners"].get(username, None)
        if spawner is None or spawner.status != "ready":
            self.close()
            return

        url = f"ws://127.0.0.1:{spawner.port}" + self.request.uri
        # override the cookie
        headers = self.request.headers.copy()
        headers["cookie"] = "key=" + spawner.hashed_password
        request = tornado.httpclient.HTTPRequest(
            url, method=self.request.method,
            headers=headers
        )
        # use request as the argument instead of url
        # so that we can set cookie when connecting websocket
        self.ws = await tornado.websocket.websocket_connect(
            request, compression_options=dict(),
            on_message_callback=self._on_upstream_message
        )

    def on_message(self, message):
        if self.ws:
            self.ws.write_message(message)

    def on_close(self):
        if self.ws:
            self.ws.close()
            self.ws = None
            self.closed = True

    def _on_upstream_message(self, message):
        if self.closed:
            if self.ws:
                self.ws.close()
                self.ws = None
        else:
            if self.ws:
                binary = isinstance(message, bytes)
                self.write_message(message, binary=binary)

    def _on_chunk(self, chunk):
        if self.proxy_error:
            return
        self.write(chunk)
        self.flush()

    def _on_headers(self, line):
        if self.proxy_error:
            return
        if line.startswith("HTTP/"):
            # the first line of the headers
            code = tornado.httputil.parse_response_start_line(line).code
            if code == 503:
                self.proxy_error = True
                return
            self.set_status(code)
            self.set_header("connection", "close")
        else:
            try:
                header = tornado.httputil.HTTPHeaders.parse(line)
                key, value = list(header.items())[0]
                key = key.lower()
            except Exception:
                return

            if key in ("connection", "server", "transfer-encoding", "date"):
                return
            if key == "content-type":
                self.set_header(key, value)
                return
            self.add_header(key, value)


class CodeServerHub(object):

    def __init__(self, args=None):
        if args is None:
            parser = build_parser()
            args = parser.parse_args([])
        handlers = [
            (r"/login", tornado.web.RedirectHandler, {"url": "/hub/login"}),
            (r"/hub/login", LoginHandler),
            (r"/hub/error/(?P<error_code>\d*)", ErrorHandler),
            (r"/hub/", tornado.web.RedirectHandler, {"url": "/hub/login"}),
            (r"/hub/admin/user/[a-zA-Z0-9]+/.*", CodeServerProxyHandler),
            (r"/.*", CodeServerProxyHandler)
        ]
        settings = {
            "template_path": os.path.join(os.path.dirname(__file__), "templates"),
            "static_path": os.path.join(os.path.dirname(__file__), "static"),
            "static_url_prefix": "/hub/static/",
            "login_url": "/hub/login",
            "cookie_secret": self._get_cookie_secret(args.cookie_secret_file),
            "args": args,
            "ip": args.ip,
            "port": args.port,
            "spawner_cmd": args.spawner_cmd,
            "admin_users": set(args.admin_users),
            "spawners": dict(),
            "compress_response": True
        }
        self.settings = settings
        self.tornado_application = tornado.web.Application(handlers, **settings)
        self.init_signal()

    def _get_cookie_secret(self, cookie_secret_file=None):
        """Load cookie_secret from file or generate a new one."""
        if cookie_secret_file is None:
            cookie_secret_file = Path("/srv/code-server-hub/cookie-secret")
        cookie_secret_file.parent.mkdir(parents=True, exist_ok=True)
        if not cookie_secret_file.exists():
            cookie_secret = random_hash_str()
            with open(cookie_secret_file, "a+") as f:
                f.write(cookie_secret)
            os.chmod(cookie_secret_file, stat.S_IWUSR | stat.S_IRUSR)
            return cookie_secret.encode()
        else:
            with open(cookie_secret_file, "rb") as f:
                return f.read().strip()

    async def start(self):
        self.http_server = tornado.httpserver.HTTPServer(self.tornado_application)
        self.http_server.listen(int(self.settings["port"]))

    def init_signal(self):
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(
                sig, lambda: asyncio.ensure_future(self.shutdown_cancel_tasks())
            )

    async def shutdown_cancel_tasks(self):
        await self.cleanup()
        asyncio.get_event_loop().stop()

    async def cleanup(self):
        for spawner in self.settings["spawners"].values():
            await spawner.stop()

    @classmethod
    def launch_instance(cls, args=None):
        self = cls(args)
        loop = IOLoop.current()
        task = asyncio.ensure_future(self.start())
        loop.start()
        if task.done():
            task.result()
        loop.stop()
        loop.close()


def build_parser():
    from . import __version__
    parser = configargparse.ArgParser(
        add_config_file_help=False,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add(
        "-c", "--config", is_config_file_arg=True,
        help="The config file to load."
    )
    parser.add(
        "--ip", default="0.0.0.0", type=str,
        help="the public facing ip of the code-server-hub."
    )
    parser.add(
        "--port", default=18000, type=int,
        help="the public facing port of the code-server-hub."
    )
    parser.add(
        "--spawner-cmd", default="code-server", type=str,
        help="the command that is used to spawn code-server. "
    )
    parser.add(
        "--cookie-secret-file", type=Path,
        default=Path("/srv/code-server-hub/cookie-secret"),
        help="the file to store cookie secret. "
    )
    parser.add(
        "--admin-users", type=str, nargs="*", default=list(),
        help="administrator user(s) of code-server-hub."
    )
    parser.add(
        "-v", "--version", action="version", version=str(__version__)
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    CodeServerHub.launch_instance(args)


if __name__ == "__main__":
    main()
