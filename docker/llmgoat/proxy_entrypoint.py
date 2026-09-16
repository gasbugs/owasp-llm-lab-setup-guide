#!/usr/bin/env python3
"""Mount the pinned upstream LLMGoat application below /llmgoat."""

from __future__ import annotations

from flask import request
from llmgoat.app import app, main


MOUNT_PATH = "/llmgoat"


class UriPrefixMiddleware:
    """Convert the public prefix into the WSGI mount path."""

    def __init__(self, wrapped_app):
        self.wrapped_app = wrapped_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path == MOUNT_PATH or path.startswith(f"{MOUNT_PATH}/"):
            environ["SCRIPT_NAME"] = MOUNT_PATH
            environ["PATH_INFO"] = path[len(MOUNT_PATH) :] or "/"
        return self.wrapped_app(environ, start_response)


app.wsgi_app = UriPrefixMiddleware(app.wsgi_app)


@app.after_request
def preserve_absolute_upstream_urls(response):
    """Keep upstream absolute UI assets and API calls inside the mount path."""

    if request.environ.get("SCRIPT_NAME") != MOUNT_PATH:
        return response
    if response.mimetype not in {
        "text/html",
        "text/css",
        "application/javascript",
        "text/javascript",
    }:
        return response

    # Flask serves static files in direct-passthrough mode. Disable that mode
    # before reading the body so CSS and JavaScript do not fail with HTTP 500.
    response.direct_passthrough = False
    body = response.get_data(as_text=True)
    for route in ("api", "challenges", "static"):
        for quote in ('"', "'", "`"):
            body = body.replace(f"{quote}/{route}/", f"{quote}{MOUNT_PATH}/{route}/")
    body = body.replace('href="/"', f'href="{MOUNT_PATH}/"')
    response.set_data(body)
    return response


if __name__ == "__main__":
    main()
