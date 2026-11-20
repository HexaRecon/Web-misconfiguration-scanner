"""Intentionally misconfigured local-only demo site for scanner testing."""

from flask import Flask, Response

demo = Flask(__name__)


@demo.route("/")
def home():
    return "Local scanner demo site"


@demo.route("/uploads/")
def uploads():
    return (
        "<html><head><title>Index of /uploads</title></head>"
        "<body><h1>Index of /uploads</h1><a href='sample.txt'>sample.txt</a></body></html>"
    )


@demo.route("/phpinfo.php")
def phpinfo():
    return "<html><body><h1>PHP Version</h1><p>phpinfo()</p></body></html>"


@demo.route("/.env")
def exposed_env():
    # Dummy value demonstrates that scanner evidence never stores file contents.
    return Response("APP_ENV=local\nDEMO_ONLY=dummy\n", content_type="text/plain")


if __name__ == "__main__":
    demo.run(host="127.0.0.1", port=8000, debug=False)
