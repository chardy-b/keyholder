import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_sdk_pin_is_in_pyproject_and_installed_on_the_upgrade_path():
    pin = re.search(r'"(bitwarden-sdk==[0-9.]+)"', (ROOT / "pyproject.toml").read_text()).group(1)
    script = (ROOT / "packaging/install.sh").read_text()
    assert f'BITWARDEN_SDK_REQ="{pin}"' in script
    upgrade_branch = script.split("--force-reinstall --no-deps", 1)[1].split("fi\n", 1)[0]
    assert '"$venv/bin/pip" install "$BITWARDEN_SDK_REQ"' in upgrade_branch
    assert "--upgrade" not in upgrade_branch and "--force-reinstall" not in upgrade_branch
