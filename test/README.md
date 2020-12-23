
To set up and run the tests, see the [detailed instructions here](../README.md#sshkeygen).

Sample test output:

```bash
~/GS/dev/sshfs/src/sshfs/build$ python3 -m pytest test/
============================================================================================ test session starts =============================================================================================
platform linux -- Python 3.8.5, pytest-6.2.1, py-1.10.0, pluggy-0.13.1 -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /home/user/GS/dev/sshfs/src/sshfs/build/test, configfile: pytest.ini
collected 16 items                                                                                                                                                                                           

test/test_sshfs.py::test_sshfs[True-True-0-False] PASSED                                                                                                                                               [  6%]
test/test_sshfs.py::test_sshfs[True-True-0-True] PASSED                                                                                                                                                [ 12%]
test/test_sshfs.py::test_sshfs[True-True-1-False] PASSED                                                                                                                                               [ 18%]
test/test_sshfs.py::test_sshfs[True-True-1-True] PASSED                                                                                                                                                [ 25%]
test/test_sshfs.py::test_sshfs[True-False-0-False] PASSED                                                                                                                                              [ 31%]
test/test_sshfs.py::test_sshfs[True-False-0-True] PASSED                                                                                                                                               [ 37%]
test/test_sshfs.py::test_sshfs[True-False-1-False] PASSED                                                                                                                                              [ 43%]
test/test_sshfs.py::test_sshfs[True-False-1-True] PASSED                                                                                                                                               [ 50%]
test/test_sshfs.py::test_sshfs[False-True-0-False] PASSED                                                                                                                                              [ 56%]
test/test_sshfs.py::test_sshfs[False-True-0-True] PASSED                                                                                                                                               [ 62%]
test/test_sshfs.py::test_sshfs[False-True-1-False] PASSED                                                                                                                                              [ 68%]
test/test_sshfs.py::test_sshfs[False-True-1-True] PASSED                                                                                                                                               [ 75%]
test/test_sshfs.py::test_sshfs[False-False-0-False] PASSED                                                                                                                                             [ 81%]
test/test_sshfs.py::test_sshfs[False-False-0-True] PASSED                                                                                                                                              [ 87%]
test/test_sshfs.py::test_sshfs[False-False-1-False] PASSED                                                                                                                                             [ 93%]
test/test_sshfs.py::test_sshfs[False-False-1-True] PASSED                                                                                                                                              [100%]

======================================================================================= 16 passed in 88.42s (0:01:28) ========================================================================================
```
