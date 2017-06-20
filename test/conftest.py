import sys
import pytest
import time
import re

# If a test fails, wait a moment before retrieving the captured
# stdout/stderr. When using a server process, this makes sure that we capture
# any potential output of the server that comes *after* a test has failed. For
# example, if a request handler raises an exception, the server first signals an
# error to FUSE (causing the test to fail), and then logs the exception. Without
# the extra delay, the exception will go into nowhere.
@pytest.mark.hookwrapper
def pytest_pyfunc_call(pyfuncitem):
    outcome = yield
    failed = outcome.excinfo is not None
    if failed:
        time.sleep(1)

@pytest.fixture()
def pass_capfd(request, capfd):
    '''Provide capfd object to UnitTest instances'''
    request.instance.capfd = capfd

def check_test_output(capfd):
    (stdout, stderr) = capfd.readouterr()

    # Write back what we've read (so that it will still be printed.
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)

    # Strip out false positives
    for (pattern, flags, count) in capfd.false_positives:
        cp = re.compile(pattern, flags)
        (stdout, cnt) = cp.subn('', stdout, count=count)
        if count == 0 or count - cnt > 0:
            stderr = cp.sub('', stderr, count=count - cnt)

    patterns = [ r'\b{}\b'.format(x) for x in
                 ('exception', 'error', 'warning', 'fatal', 'traceback',
                    'fault', 'crash(?:ed)?', 'abort(?:ed)',
                    'uninitiali[zs]ed') ]
    patterns += ['^==[0-9]+== ']
    for pattern in patterns:
        cp = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        hit = cp.search(stderr)
        if hit:
            raise AssertionError('Suspicious output to stderr (matched "%s")' % hit.group(0))
        hit = cp.search(stdout)
        if hit:
            raise AssertionError('Suspicious output to stdout (matched "%s")' % hit.group(0))

def register_output(self, pattern, count=1, flags=re.MULTILINE):
    '''Register *pattern* as false positive for output checking

    This prevents the test from failing because the output otherwise
    appears suspicious.
    '''

    self.false_positives.append((pattern, flags, count))

# This is a terrible hack that allows us to access the fixtures from the
# pytest_runtest_call hook. Among a lot of other hidden assumptions, it probably
# relies on tests running sequential (i.e., don't dare to use e.g. the xdist
# plugin)
current_capfd = None
@pytest.yield_fixture(autouse=True)
def save_cap_fixtures(request, capfd):
    global current_capfd
    capfd.false_positives = []

    # Monkeypatch in a function to register false positives
    type(capfd).register_output = register_output

    if request.config.getoption('capture') == 'no':
        capfd = None
    current_capfd = capfd
    bak = current_capfd
    yield

    # Try to catch problems with this hack (e.g. when running tests
    # simultaneously)
    assert bak is current_capfd
    current_capfd = None

@pytest.hookimpl(trylast=True)
def pytest_runtest_call(item):
    capfd = current_capfd
    if capfd is not None:
        check_test_output(capfd)
