from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass(slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner:
    """Runs argv arrays without invoking a shell.

    Adapters construct every argument and validate all user-controlled values
    before they reach this class.
    """

    def exists(self, executable: str) -> bool:
        return shutil.which(executable) is not None

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = 8,
        input_text: str | None = None,
        allowed_returncodes: Iterable[int] = (0,),
    ) -> CommandResult:
        if not argv or not isinstance(argv[0], str):
            raise ValueError("invalid argv")
        completed = subprocess.run(
            list(argv),
            check=False,
            shell=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            input=input_text,
            timeout=timeout,
            env={
                "PATH": os.environ.get(
                    "PATH",
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                ),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
        result = CommandResult(
            tuple(str(item) for item in argv),
            completed.returncode,
            completed.stdout,
            completed.stderr,
        )
        if completed.returncode not in set(allowed_returncodes):
            return result
        return result


class FakeRunner(CommandRunner):
    """Small deterministic runner used by tests and downstream integrations."""

    def __init__(
        self,
        responses: dict[tuple[str, ...], CommandResult] | None = None,
        executables: set[str] | None = None,
    ) -> None:
        self.responses = responses or {}
        self.executables = executables or set()
        self.calls: list[tuple[str, ...]] = []

    def exists(self, executable: str) -> bool:
        return executable in self.executables

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = 8,
        input_text: str | None = None,
        allowed_returncodes: Iterable[int] = (0,),
    ) -> CommandResult:
        key = tuple(argv)
        self.calls.append(key)
        return self.responses.get(key, CommandResult(key, 127, "", "not mocked"))

