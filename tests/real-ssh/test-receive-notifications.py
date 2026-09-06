"""Run inside the disposable runner under dbus-run-session, with real notify-send."""
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import threading
import time
import traceback

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

INTERFACE = "org.freedesktop.Notifications"
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
name = dbus.service.BusName(INTERFACE, bus)
loop = GLib.MainLoop()
observed = []
errors = []
choice = "deny"


class Notifications(dbus.service.Object):
    @dbus.service.method(INTERFACE, in_signature="", out_signature="as")
    def GetCapabilities(self):
        return ["actions", "body", "body-markup"]

    @dbus.service.method(INTERFACE, in_signature="", out_signature="ssss")
    def GetServerInformation(self):
        return "syq test", "syq", "1", "1.2"

    @dbus.service.method(INTERFACE, in_signature="susssasa{sv}i", out_signature="u")
    def Notify(self, app, replace, icon, summary, body, actions, hints, expiry):
        observed.append((str(app), str(summary), str(body), list(actions), int(expiry)))
        notification_id = len(observed)
        selected = choice
        if selected == "unavailable":
            raise dbus.exceptions.DBusException("Desktop unavailable in test", name="org.freedesktop.DBus.Error.Failed")

        def answer():
            if selected != "dismiss":
                self.ActionInvoked(notification_id, selected)
            self.NotificationClosed(notification_id, 2)
            return False

        GLib.timeout_add(200, answer)
        return notification_id

    @dbus.service.method(INTERFACE, in_signature="u", out_signature="")
    def CloseNotification(self, notification_id):
        self.NotificationClosed(notification_id, 3)

    @dbus.service.signal(INTERFACE, signature="us")
    def ActionInvoked(self, notification_id, action):
        pass

    @dbus.service.signal(INTERFACE, signature="uu")
    def NotificationClosed(self, notification_id, reason):
        pass


service = Notifications(bus, "/org/freedesktop/Notifications")


def run(*args, success=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    assert (result.returncode == 0) == success, (args, result)
    return result.stdout


def wait_notification_status(expected):
    deadline = time.monotonic() + 10
    progress = time.monotonic() + 5
    while True:
        pending = json.loads(run("syq", "recv", "pending", "--json"))
        if len(pending) == 1 and pending[0]["notification"].startswith(expected):
            return pending[0]
        assert time.monotonic() < deadline, ("prompt did not finish", pending)
        if time.monotonic() >= progress:
            print("Waiting for notification result:", pending, flush=True)
            progress += 5
        time.sleep(.05)


def tests():
    global choice
    try:
        run("syq", "recv", "on", "--approve", "ask", "--notify", "desktop")
        run("syq", "recv", "wait", "source", "--timeout", "30")
        for choice in ["allow", "deny", "dismiss", "unexpected", "unavailable"]:
            destination = Path("/tmp/syq-real-ssh-receive") / f"desktop-{choice}-<b>&"
            command = shlex.join([
                "syq", "cp", "/tmp/syq-real-ssh/return-source/message.txt",
                "--to", "@laptop", "--as", destination.name,
            ])
            copy = subprocess.Popen(["ssh", "source", command], start_new_session=True)
            try:
                if choice in ["dismiss", "unexpected", "unavailable"]:
                    pending = wait_notification_status("unavailable" if choice == "unavailable" else "dismissed")
                    assert not destination.exists()
                    assert copy.poll() is None, "dismissal completed the copy"
                    run("syq", "recv", "deny", pending["id"])
                assert (copy.wait(timeout=20) == 0) == (choice == "allow")
                assert destination.exists() == (choice == "allow")
                if choice == "allow":
                    assert destination.read_bytes() == b"return\n"
                app, summary, body, actions, expiry = observed[-1]
                assert app == "syq" and summary == "syq: incoming copy"
                assert "&lt;b&gt;&amp;" in body and "<b>" not in body, body
                assert "source" in body and "May create and overwrite" in body, body
                assert "at most 0 deletions" in body and "not been inspected" in body, body
                assert actions == ["allow", "Allow once", "deny", "Deny"], actions
                assert expiry == 300000
                assert json.loads(run("syq", "recv", "pending", "--json")) == []
                print(f"Notification action {choice}: passed", flush=True)
            finally:
                try:
                    os.killpg(copy.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                copy.wait()
        assert len(observed) == 5, observed
    except BaseException:
        errors.append(traceback.format_exc())
    finally:
        try:
            run("syq", "recv", "on", "--notify", "off")
            run("syq", "recv", "wait", "source", "--timeout", "30")
        except BaseException:
            errors.append(traceback.format_exc())
        GLib.idle_add(loop.quit)


task = threading.Thread(target=tests)
task.start()
loop.run()
task.join()
assert not errors, "\n".join(errors)
