import runpy
import sys
from io import StringIO
from contextlib import redirect_stdout
import pytest


def run_cli(args, expect_exit=True):
    argv = sys.argv[:]
    sys.argv = ["glacier.py", *args]
    sys.path.insert(0, "src")
    out = StringIO()
    try:
        if expect_exit:
            with redirect_stdout(out), pytest.raises(SystemExit) as exc:
                runpy.run_path("src/glacier.py", run_name="__main__")
            code = exc.value.code
        else:
            with redirect_stdout(out):
                runpy.run_path("src/glacier.py", run_name="__main__")
            code = 0
    finally:
        sys.argv = argv
        sys.path.pop(0)
    return code, out.getvalue()


def test_help():
    code, output = run_cli(["--help"])
    assert code == 0
    assert "Glacier" in output


def test_version():
    code, output = run_cli(["-v"])
    assert code == 0
    assert "Glacier v" in output
