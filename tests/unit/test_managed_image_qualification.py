"""Qualification wheels are approved fixtures, not live dependency resolution."""
import copy
from pathlib import Path
import zipfile

import pytest

from tools.managed_image import Refused, file_record, read_json
from tools.managed_image_qualification import check_wheel, validate_plan


def plan():
    path = Path(__file__).parents[2] / "docker/managed-image-qualification.json"
    return read_json(path.read_bytes())


def test_finite_qualification_plan_accepts_recorded_candidate():
    validate_plan(plan())


@pytest.mark.parametrize("mutation", [
    lambda value: value["wheels"][0].update(url="https://unapproved.invalid/a.whl"),
    lambda value: value["wheels"][0].update(filename="../pip.whl"),
    lambda value: value["wheels"][0].update(size=True),
    lambda value: value["wheels"].append(copy.deepcopy(value["wheels"][0])),
    lambda value: value["discovery"].update(reserved_transfer_bytes=1),
    lambda value: value.update(python=[3, 11]),
])
def test_qualification_substitutions_refuse(mutation):
    value = plan()
    mutation(value)
    with pytest.raises(Refused):
        validate_plan(value)


def test_seed_wheel_uses_one_top_level_metadata_record(tmp_path):
    path = tmp_path / "pip-25.3-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("pip-25.3.dist-info/METADATA", "Name: pip\nVersion: 25.3\n")
        archive.writestr("pip/_vendor/vendor-1.dist-info/METADATA", "Name: vendor\nVersion: 1\n")
    record = file_record(path) | {"name": "pip", "version": "25.3"}
    check_wheel(path, record)
    record["version"] = "0.0"
    with pytest.raises(Refused, match="name/version"):
        check_wheel(path, record)
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("other-1.dist-info/METADATA", "Name: other\nVersion: 1\n")
    with pytest.raises(Refused, match="ambiguous"):
        check_wheel(path, file_record(path) | {"name": "pip", "version": "25.3"})
