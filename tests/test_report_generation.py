import os
import sys
import socket
from pathlib import Path
import runpy
from io import StringIO
from contextlib import redirect_stdout
import yaml
import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]


def test_report_generation(tmp_path):
    argv = sys.argv[:]
    sys.argv = ["glacier.py", "-w", "1", "-t", "1", "--no-s3"]
    sys.path.insert(0, str(ROOT_DIR / "src"))
    out = StringIO()
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        with redirect_stdout(out):
            runpy.run_path(str(ROOT_DIR / 'src' / 'glacier.py'), run_name="__main__")
        code = 0
    except Exception as exc:
        err_msg = str(exc).lower()
        if (
            'address family not supported' in err_msg
            or 'operation not permitted' in err_msg
        ):
            pytest.skip('network features unavailable in this environment')
        raise
    finally:
        os.chdir(old_cwd)
        sys.argv = argv
        sys.path.pop(0)
    if code != 0:
        err = out.getvalue().lower()
        if 'address family not supported' in err or 'operation not permitted' in err:
            pytest.skip('network features unavailable in this environment')
        assert code == 0, out.getvalue()
    hostname = socket.gethostname()
    yaml_file = tmp_path / f"{hostname}_linux_report_analyzer.yaml"
    html_file = tmp_path / f"{hostname}_linux_report_analyzer.html"
    assert yaml_file.exists()
    assert html_file.exists()
    with open(yaml_file) as f:
        data = yaml.safe_load(f)
    assert 'netflow_message' in data
