"""Desktop process boundaries and worker recovery without a graphical display."""

from pathlib import Path
import queue
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from vps_proxy_setup.cli import SetupError
from vps_proxy_setup.desktop import app


class ConsoleCommandTests(unittest.TestCase):
    def test_source_uses_installed_console_module_and_separate_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            python = Path(directory) / "python.exe"
            config = Path(directory) / "folder with spaces" / "request.json"
            with patch.object(app.sys, "frozen", False, create=True), patch.object(app.sys, "executable", str(python)):
                command = app.console_command(config, ssh_only=True)
            self.assertEqual(command, [str(python), "-m", "vps_proxy_setup.desktop.console", "--config", str(config), "--ssh-only"])

    def test_pythonw_switches_to_console_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            python = Path(directory) / "python.exe"
            python.touch()
            with patch.object(app.sys, "frozen", False, create=True), patch.object(app.sys, "executable", str(python.with_name("pythonw.exe"))):
                command = app.console_command(Path(directory) / "request.json")
            self.assertEqual(command[0], str(python))
            self.assertNotIn("--ssh-only", command)

    def test_pythonw_without_console_interpreter_stops_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(app.sys, "frozen", False, create=True), patch.object(app.sys, "executable", str(Path(directory) / "pythonw.exe")):
                with self.assertRaisesRegex(SetupError, "python.exe"):
                    app.console_command(Path(directory) / "request.json")

    def test_frozen_uses_console_sibling_regardless_of_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            gui = Path(directory) / "Proxy-Setup-Assistant.exe"
            helper = gui.with_name("Proxy-Setup-Console.exe")
            helper.touch()
            config = Path(directory) / "request with spaces.json"
            with patch.object(app.sys, "frozen", True, create=True), patch.object(app.sys, "executable", str(gui)):
                self.assertEqual(app.console_command(config), [str(helper), "--config", str(config)])

    def test_incomplete_frozen_distribution_stops_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(app.sys, "frozen", True, create=True), patch.object(app.sys, "executable", str(Path(directory) / "Proxy-Setup-Assistant.exe")):
                with self.assertRaisesRegex(SetupError, "Proxy-Setup-Console.exe"):
                    app.console_command(Path(directory) / "request.json")


class WorkerRecoveryTests(unittest.TestCase):
    def wizard(self):
        wizard = app.Wizard.__new__(app.Wizard)
        wizard.root = Mock()
        wizard.root.winfo_exists.return_value = True
        wizard.busy = False
        wizard.events = queue.Queue()
        wizard.status = Mock()
        wizard.progress = Mock()
        wizard._toggle = Mock()
        return wizard

    def run_worker(self, wizard, task, completed):
        # Run the worker deterministically while preserving its queue boundary.
        with patch.object(app.threading, "Thread", side_effect=lambda *, target, daemon: SimpleNamespace(start=target)):
            wizard.work("checking", task, completed)
        wizard.pump()

    def test_unexpected_failure_recovers_controls_without_disclosing_url(self):
        wizard = self.wizard()
        completed = Mock()
        private = "https://example.org/private?token=TEST_ONLY_private"
        with patch.object(app.messagebox, "showerror") as showerror:
            self.run_worker(wizard, Mock(side_effect=RuntimeError(private)), completed)
        self.assertFalse(wizard.busy)
        self.assertEqual([call.args[0] for call in wizard._toggle.call_args_list], [False, True])
        wizard.progress.stop.assert_called_once()
        completed.assert_not_called()
        showerror.assert_called_once()
        self.assertNotIn(private, str(showerror.call_args))
        self.assertNotIn(private, str(wizard.status.set.call_args_list))
        wizard.root.after.assert_called_once_with(100, wizard.pump)
        self.assertTrue(wizard.events.empty())

    def test_success_delivers_result_and_restores_controls(self):
        wizard = self.wizard()
        result = object()
        completed = Mock()
        with patch.object(app.messagebox, "showerror") as showerror:
            self.run_worker(wizard, lambda: result, completed)
        completed.assert_called_once_with(result)
        showerror.assert_not_called()
        self.assertFalse(wizard.busy)
        wizard._toggle.assert_called_with(True)

    def test_busy_operation_does_not_start_a_second_worker(self):
        wizard = self.wizard()
        wizard.busy = True
        with patch.object(app.threading, "Thread") as thread:
            wizard.work("duplicate", Mock(), Mock())
        thread.assert_not_called()


if __name__ == "__main__":
    unittest.main()
