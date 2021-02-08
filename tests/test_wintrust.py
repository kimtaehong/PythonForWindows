import sys
import pytest
import glob

import windows
import windows.generated_def as gdef

from pfwtest import *
from windows.pycompat import is_py3

pytestmark = pytest.mark.usefixtures('check_for_gc_garbage')


def test_script_file_not_signed():
    assert not windows.wintrust.is_signed(__file__)
    assert windows.wintrust.check_signature(__file__) == gdef.TRUST_E_SUBJECT_FORM_UNKNOWN


if is_py3:
    # Py3 binaries are signed
    def test_python_signature():
        python_path = sys.executable
        assert windows.wintrust.is_signed(python_path)
        assert windows.wintrust.check_signature(python_path) == 0
else:
    # Py2 binaries are NOT signed
    def test_python_signature():
        python_path = sys.executable
        assert not windows.wintrust.is_signed(python_path)
        assert windows.wintrust.check_signature(python_path) == gdef.TRUST_E_NOSIGNATURE


def test_kernel32_signed():
    k32_path = r"C:\windows\system32\kernel32.dll"
    assert windows.wintrust.is_signed(k32_path)
    assert windows.wintrust.check_signature(k32_path) == 0


def test_verify_file():
    chrome_path = r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    verify_result, signer_names = windows.wintrust.verify_file_ex(chrome_path)

    uwp_app_path = r'C:\Windows\System32\calc.exe'
    verify_result, signer_names = windows.wintrust.verify_file_ex(uwp_app_path)

    assert verify_result == windows.wintrust.VerifyResult.VrTrusted

    test_path_list = []
    for file_path in glob.glob(f'c:\\windows\\system32\\*.*'):
        test_path_list.append(file_path)

    for file_path in glob.glob(f'c:\\windows\\system32\\*.exe'):
        test_path_list.append(file_path)

    for file_path in glob.glob(f'c:\\windows\\system32\\*.sys'):
        test_path_list.append(file_path)

    for test_path in test_path_list:
        verify_result, signer_names = windows.wintrust.verify_file_ex(test_path)
        print(verify_result, ','.join(signer_names))
