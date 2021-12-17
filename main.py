import base64
import asyncio
import os
import logging
from pathlib import Path
import shutil
import subprocess
import sys
import traceback

import json

import aiohttp
from aiohttp import web
import cachetools

from dotenv import load_dotenv

from gidgethub import aiohttp as gh_aiohttp
from gidgethub import routing
from gidgethub import sansio
from gidgethub import apps
from git import Repo

import sentry_sdk
from sentry_sdk.integrations.aiohttp import AioHttpIntegration

import pii_secret_check_hooks

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gh-secret-scanner-bot")

load_dotenv()

router = routing.Router()
cache = cachetools.LRUCache(maxsize=500)

routes = web.RouteTableDef()

sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN"),
    integrations=[AioHttpIntegration()]
)

BASE_PII_PACKAGE_PATH = PurePath(pii_secret_check_hooks.__file__).parent

CHECKS = [
    BASE_PII_PACKAGE_PATH / PurePath("pii_secret_filename.py"),
    BASE_PII_PACKAGE_PATH / PurePath("pii_secret_file_content.py"),
    BASE_PII_PACKAGE_PATH / PurePath("pii_secret_file_content_ner.py"),
]


def clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    return project_path


def run_checks(project_path, files):
    base_path = PurePath(project_path)
    _files = [str(base_path / PurePath(file_)) for file_ in files]

    command_output = []

    for command in CHECKS:
        output = subprocess.run([sys.executable, command, *_files], capture_output=True, text=True)

        command_output.append(output.stdout)

    output_text = "\n".join(output for output in command_output if output.strip())

    return None if not output_text else output_text.replace(project_path, "")


async def slack_notify(app, message):
    payload = {
        "text": message
    }

    await app["client_session"].post(os.environ["SLACK_NOTIFY_URL"], json=payload)


@routes.get("/", name="home")
async def handle_get(request):
    return web.Response(text="Github Vuln Scanner")


@routes.post("/webhook")
async def webhook(request):
    try:
        body = await request.read()
        secret = os.environ.get("GITHUB_WEBHOOK_SECRET")
        event = sansio.Event.from_http(request.headers, body, secret=secret)

        if event.event == "ping":
            return web.Response(status=200)

        gh = gh_aiohttp.GitHubAPI(request.app["client_session"], "demo", cache=cache)

        await asyncio.sleep(1)
        await router.dispatch(event, gh, app=request.app)

        try:
            print("GH requests remaining:", gh.rate_limit.remaining)
        except AttributeError:
            pass
        return web.Response(status=200)
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return web.Response(status=500)


@router.register("installation", action="created")
async def repo_installation_added(event, gh, *args, **kwargs):
    installation_id = event.data["installation"]["id"]

    installation_access_token = await apps.get_installation_access_token(
        gh,
        installation_id=installation_id,
        app_id=os.environ.get("GITHUB_APP_ID"),
        private_key=base64.b64decode(os.environ.get("GITHUB_PRIVATE_KEY")).decode("utf-8")
    )
    repo_name = event.data["repositories"][0]["full_name"]
    url = f"/repos/{repo_name}/issues"
    response = await gh.post(
        url,
                     data={
        'title': 'Thanks for installing my bot',
        'body': 'Thanks!',
            },
        oauth_token=installation_access_token["token"]
                             )
    print(response)


@router.register("push")
async def push(event, gh, app=None, *arg, **kwargs):
    """Handle push event"""

    app["worker_queue"].put_nowait(event.data)


async def worker(app):
    """worker to process commits"""

    event_loop = asyncio.get_running_loop()

    while True:
        data = await app["worker_queue"].get()

        commits = data.get("commits", [])

        if commits:
            project_path = await event_loop.run_in_executor(None, clone_git_repo, data["repository"]["git_url"])

            for commit in commits:
                await event_loop.run_in_executor(None, repo.commit, commit["id"])

                files = list(set([*commit["added"], *commit["modified"]]))

                try:
                    output = await event_loop.run_in_executor(None, run_checks, project_path, files)
                except Exception as ex:
                    await slack_notify(app, f"An error occured: {ex}")
                    continue

                if output:
                    message = f"""Possible PII violations found in:
{commit["url"]}
Author: {commit["author"]["name"]}

{output}
"""
                    await slack_notify(app, message)

            event_loop.run_in_executor(None, shutil.rmtree, project_path)

        app["worker_queue"].task_done()


async def aiohttp_session(app):
    app["client_session"] = aiohttp.ClientSession()
    yield
    await app["client_session"].close()


async def main():
    app = web.Application()

    app.cleanup_ctx.append(aiohttp_session)

    app.router.add_routes(routes)
    port = int(os.environ.get("PORT", "5000"))

    app["worker_queue"] = asyncio.Queue()

    task = asyncio.create_task(worker(app))

    await asyncio.gather(
        web._run_app(app, port=port),
        task,
    )


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(main())
