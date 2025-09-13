"""Configures pytest further."""
import pytest


def pytest_addoption(parser):
    parser.addoption("--skip-slow", action="store_true", default=False, help="skip slower tests")
    parser.addoption("--run-extreme", action="store_true", default=False, help="run extreme value extremely slow tests")


def pytest_collection_modifyitems(config, items):
    skipdict = {}
    if config.getoption("--skip-slow"):
        skipdict["slow"] = pytest.mark.skip(reason="Slow test: needs no --skip-slow option")
    if not config.getoption("--run-extreme"):
        skipdict["extreme"] = pytest.mark.skip(reason="Extreme test: needs --run-extreme option")
    if not skipdict:
        return
    for item in items:
        for k, v in skipdict.items():
            if k in item.keywords:
                item.add_marker(v)
