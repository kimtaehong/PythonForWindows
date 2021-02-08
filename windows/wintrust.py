from __future__ import print_function

import ctypes
import struct
import windows
import os
from  collections import namedtuple
from windows import winproxy
import windows.generated_def as gdef
from windows.generated_def.winstructs import *


# From: um/SoftPub.h
WINTRUST_ACTION_GENERIC_VERIFY_V2 = gdef.IID.from_string("00AAC56B-CD44-11d0-8CC2-00C04FC295EE")
DRIVER_ACTION_VERIFY = gdef.IID.from_string("F750E6C3-38EE-11d1-85E5-00C04FC295EE")

wintrust_know_return_value = [
    TRUST_E_PROVIDER_UNKNOWN,
    TRUST_E_ACTION_UNKNOWN,
    TRUST_E_SUBJECT_FORM_UNKNOWN,
    DIGSIG_E_ENCODE,
    TRUST_E_SUBJECT_NOT_TRUSTED,
    TRUST_E_BAD_DIGEST,
    DIGSIG_E_DECODE,
    DIGSIG_E_EXTENSIBILITY,
    PERSIST_E_SIZEDEFINITE,
    DIGSIG_E_CRYPTO,
    PERSIST_E_SIZEINDEFINITE,
    PERSIST_E_NOTSELFSIZING,
    TRUST_E_NOSIGNATURE,
    CERT_E_EXPIRED,
    CERT_E_VALIDITYPERIODNESTING,
    CERT_E_PURPOSE,
    CERT_E_ISSUERCHAINING,
    CERT_E_MALFORMED,
    CERT_E_UNTRUSTEDROOT,
    CERT_E_CHAINING,
    TRUST_E_FAIL,
    CERT_E_REVOKED,
    CERT_E_UNTRUSTEDTESTROOT,
    CERT_E_REVOCATION_FAILURE,
    CERT_E_CN_NO_MATCH,
    CERT_E_WRONG_USAGE,
    TRUST_E_EXPLICIT_DISTRUST,
    CERT_E_UNTRUSTEDCA,
    CERT_E_INVALID_POLICY,
    CERT_E_INVALID_NAME,
    CRYPT_E_FILE_ERROR,
]
wintrust_return_value_mapper = gdef.FlagMapper(*wintrust_know_return_value)


def check_signature(filename):
    """Check if ``filename`` embeds a valid signature.

        :return: :class:`int`: ``0`` if ``filename`` have a valid signature else the error
    """
    file_data = WINTRUST_FILE_INFO()
    file_data.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_data.pcwszFilePath = filename
    file_data.hFile = None
    file_data.pgKnownSubject = None

    WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2

    win_trust_data = WINTRUST_DATA()
    win_trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    win_trust_data.pPolicyCallbackData = None
    win_trust_data.pSIPClientData = None
    win_trust_data.dwUIChoice = WTD_UI_NONE
    # win_trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
    win_trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN
    win_trust_data.dwUnionChoice = WTD_CHOICE_FILE
    win_trust_data.dwStateAction = WTD_STATEACTION_VERIFY
    win_trust_data.hWVTStateData = None
    win_trust_data.pwszURLReference = None
    win_trust_data.dwUIContext = 0

    #win_trust_data.dwProvFlags  = 0x1000 + 0x10 + 0x800
    win_trust_data.tmp_union.pFile = ctypes.pointer(file_data)

    x = winproxy.WinVerifyTrust(None, ctypes.byref(WVTPolicyGUID), ctypes.byref(win_trust_data))
    win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE
    winproxy.WinVerifyTrust(None, ctypes.byref(WVTPolicyGUID), ctypes.byref(win_trust_data))
    return wintrust_return_value_mapper[x & 0xffffffff]


def get_catalog_for_filename(filename):
    ctx = HCATADMIN()
    winproxy.CryptCATAdminAcquireContext(ctypes.byref(ctx), DRIVER_ACTION_VERIFY, 0)
    hash = get_file_hash(filename)
    if hash is None:
        return None
    t = winproxy.CryptCATAdminEnumCatalogFromHash(ctx, hash, len(hash), 0, None)
    if t is None:
        return None
    tname = get_catalog_name_from_handle(t)

    while t is not None:
        t = winproxy.CryptCATAdminEnumCatalogFromHash(ctx, hash, len(hash), 0, ctypes.byref(HCATINFO(t)))
        # Todo: how to handle multiple catalog ?
    winproxy.CryptCATAdminReleaseCatalogContext(ctx, t, 0)
    winproxy.CryptCATAdminReleaseContext(ctx, 0)
    return tname


def get_file_hash(filename):
    f = open(filename, "rb")
    handle = windows.utils.get_handle_from_file(f)

    size = DWORD(0)
    x = winproxy.CryptCATAdminCalcHashFromFileHandle(handle, ctypes.byref(size), None, 0)
    buffer = (BYTE * size.value)()
    try:
        x = winproxy.CryptCATAdminCalcHashFromFileHandle(handle, ctypes.byref(size), buffer, 0)
    except WindowsError as e:
        if e.winerror == 1006:
            # CryptCATAdminCalcHashFromFileHandle: [Error 1006]
            # The volume for a file has been externally altered so that the opened file is no longer valid.
            # (returned for empty file)
            return None
        raise
    return buffer


def get_file_hash2(filename): #POC: name/API will change/disapear
    f = open(filename, "rb")
    handle = windows.utils.get_handle_from_file(f)

    cathand = HANDLE()
    h = winproxy.CryptCATAdminAcquireContext2(cathand, None, "SHA256", None, 0)
    print(cathand)

    size = DWORD(0)
    x = winproxy.CryptCATAdminCalcHashFromFileHandle2(cathand, handle, ctypes.byref(size), None, 0)
    buffer = (BYTE * size.value)()
    try:
        x = winproxy.CryptCATAdminCalcHashFromFileHandle2(cathand, handle, ctypes.byref(size), buffer, 0)
    except WindowsError as e:
        if e.winerror == 1006:
            # CryptCATAdminCalcHashFromFileHandle: [Error 1006]
            # The volume for a file has been externally altered so that the opened file is no longer valid.
            # (returned for empty file)
            return None
        raise
    return buffer


def get_catalog_name_from_handle(handle):
    cat_info = CATALOG_INFO()
    cat_info.cbStruct = ctypes.sizeof(cat_info)
    winproxy.CryptCATCatalogInfoFromContext(handle, ctypes.byref(cat_info), 0)
    return cat_info.wszCatalogFile


SignatureData = namedtuple("SignatureData", ["signed", "catalog", "catalogsigned", "additionalinfo"])
"""Signature information for ``FILENAME``:

    * ``signed``: True if ``FILENAME`` embeds a valide signature
    * ``catalog``: The filename of the catalog ``FILENAME`` is part of (if any)
    * ``catalogsigned``: True if ``catalog`` embeds a valide signature
    * ``additionalinfo``: The return error of ``check_signature(FILENAME)``

``additionalinfo`` is useful to know if ``FILENAME`` signature was rejected for an invalid root / expired cert.
"""


def full_signature_information(filename):
    """Returns more information about the signature of ``filename``

    :return: :class:`SignatureData`
    """
    check_sign = check_signature(filename)
    signed = not bool(check_sign)
    catalog = get_catalog_for_filename(filename)
    if catalog is None:
        return SignatureData(signed, None, False, check_sign)
    catalogsigned = not bool(check_signature(catalog))
    return SignatureData(signed, catalog, catalogsigned, check_sign)


def is_signed(filename):
    """Check if ``filename`` is signed:

        * File embeds a valid signature
        * File is part of a signed catalog file

    :return: :class:`bool`
    """
    check_sign = check_signature(filename)
    if check_sign == 0:
        return True
    catalog = get_catalog_for_filename(filename)
    if catalog is None:
        return False
    catalogsigned = not bool(check_signature(catalog))
    return catalogsigned


verify_default_size_limit = 32 * 1024 * 1024


class VerifyResult:
    VrUnknown = 0
    VrNoSignature = 1
    VrTrusted = 2
    VrExpired = 3
    VrRevoked = 4
    VrDistrust = 5
    # cryptographic operation failed due to a local security option setting.
    VrSecuritySettings = 6
    VrBadSignature = 7


class SignatureInfo:
    _number_of_signatures = 0
    _signatures = []
    _result = VerifyResult.VrUnknown

    def __init__(self, number_of_signatures, signatures, result):
        self._number_of_signatures = number_of_signatures
        self._signatures = signatures
        self._result = result


class VerifyFileInfo:
    file_path = None
    file_handle = None
    flag = 0
    file_size_limit_for_hash = 0
    number_of_catalog_file_names = 0
    catalog_file_names = None
    secondary_signatures = []
    hwnd = None

    def __del__(self):
        winproxy.CloseHandle(self.file_handle)
        self.secondary_signatures.clear()


_int_to_char_table = "0123456789abcdefghijklmnopqrstuvwxyz !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
_int_to_uchar_table = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"


def bin_to_hexw_fast(size, buffer, upper_case):
    hex_buffer = create_unicode_buffer(size * 2)
    if upper_case:
        table = _int_to_uchar_table
    else:
        table = _int_to_char_table
    for idx in range(size):
        hex_buffer[idx * 2] = table[buffer[idx] >> 4]
        hex_buffer[idx * 2 + 1] = table[buffer[idx] & 0xf]
    return hex_buffer


def status_to_verify_result(status):
    if status == 0:
        return VerifyResult.VrTrusted
    if status == HRESULT(TRUST_E_NOSIGNATURE).value:
        return VerifyResult.VrNoSignature
    if status == HRESULT(CERT_E_EXPIRED).value:
        return VerifyResult.VrExpired
    if status == HRESULT(CERT_E_REVOKED).value:
        return VerifyResult.VrRevoked
    if status == HRESULT(TRUST_E_EXPLICIT_DISTRUST).value:
        return VerifyResult.VrDistrust
    if status == HRESULT(CRYPT_E_SECURITY_SETTINGS).value:
        return VerifyResult.VrSecuritySettings
    if status == HRESULT(TRUST_E_BAD_DIGEST).value:
        return VerifyResult.VrBadSignature
    return VerifyResult.VrSecuritySettings


def get_cert_name_string(subject):
    subject_size = winproxy.CertNameToStrW(
            X509_ASN_ENCODING,
            subject,
            CERT_X500_NAME_STR,
            None,
            0
        )

    buffer = create_unicode_buffer(subject_size)
    subject_size = winproxy.CertNameToStrW(
        X509_ASN_ENCODING,
        subject,
        CERT_X500_NAME_STR,
        buffer,
        subject_size
    )
    assert subject_size >= 0
    return buffer.value


def get_x500_value(value, key):
    ptrn = f'{key}='
    sidx = value.find(ptrn)
    if sidx == -1:
        return None

    token = value[sidx+len(ptrn):]
    if token[0] != '\"':
        eidx = value.find(',', sidx)
        if eidx != -1:
            return value[sidx:eidx].replace(ptrn, '').strip()
        return value[sidx:].replace(ptrn, '').strip()
    else:
        token = token[1:]
        return token[:token.find('\"')].strip()


def get_signer_name_from_certificate(certificate):
    assert certificate is not None
    try:
        cert_info = certificate.contents.pCertInfo
    except ValueError:
        return ""
    else:
        name = get_cert_name_string(cert_info.contents.Subject)

        cn_or_ou = get_x500_value(name, 'CN')
        if cn_or_ou is None:
            cn_or_ou = get_x500_value(name, 'OU')
        return '' if cn_or_ou is None else cn_or_ou


def calculate_file_hash(file_handle, hash_algorithm):
    cat_admin_handle = HANDLE()
    if hasattr(winproxy, 'CryptCATAdminAcquireContext2'):
        if winproxy.CryptCATAdminAcquireContext2(
            cat_admin_handle,
            DRIVER_ACTION_VERIFY,
            hash_algorithm,
            None,
            0
        ) is False:
            return None, 0, None
    else:
        if winproxy.CryptCATAdminAcquireContext(cat_admin_handle, DRIVER_ACTION_VERIFY, 0) is False:
            return None, 0, None

    file_hash_length = DWORD(0)
    if hasattr(winproxy, 'CryptCATAdminCalcHashFromFileHandle2'):
        _ = winproxy.CryptCATAdminCalcHashFromFileHandle2(cat_admin_handle,
                                                          file_handle, ctypes.byref(file_hash_length), None, 0)
        file_hash = (BYTE * file_hash_length.value)()
        try:
            ret = winproxy.CryptCATAdminCalcHashFromFileHandle2(cat_admin_handle,
                                                                file_handle,
                                                                ctypes.byref(file_hash_length), file_hash, 0)
        except WindowsError as ex:
            print(f"CryptCATAdminCalcHashFromFileHandle2() failed. ex={str(ex)}")
            return None, 0, None
    else:
        _ = winproxy.CryptCATAdminCalcHashFromFileHandle(file_handle, ctypes.byref(file_hash_length), None, 0)
        file_hash = (BYTE * file_hash_length.value)()
        try:
            ret = winproxy.CryptCATAdminCalcHashFromFileHandle(file_handle,
                                                               ctypes.byref(file_hash_length), file_hash, 0)
        except WindowsError as ex:
            print(f"CryptCATAdminCalcHashFromFileHandle2() failed. ex={str(ex)}")
            return None, 0, None

    if ret is False:
        return None, 0, None
    else:
        return cat_admin_handle, file_hash_length.value, file_hash


def verify_file_from_catalog(verify_file_info, hash_algorithm=None):
    result = VerifyResult.VrNoSignature

    if verify_file_info.file_size_limit_for_hash != -1:
        file_size_limit = verify_default_size_limit
        if verify_file_info.file_size_limit_for_hash != 0:
            file_size_limit = verify_file_info.file_size_limit_for_hash
        if os.path.getsize(verify_file_info.file_path) > file_size_limit:
            return result, 0, None

    cat_admin_handle, file_hash_length, file_hash = calculate_file_hash(verify_file_info.file_handle, hash_algorithm)
    if cat_admin_handle is None or file_hash_length == 0 or file_hash is None:
        return result, 0, None

    file_hash_tag = bin_to_hexw_fast(file_hash_length, file_hash, True)
    cat_info_handle = winproxy.CryptCATAdminEnumCatalogFromHash(
        cat_admin_handle,
        file_hash,
        file_hash_length,
        0,
        None
    )

    catalog_info = WINTRUST_CATALOG_INFO()
    catalog_info.cbStruct = ctypes.sizeof(catalog_info)

    verify_result = VerifyResult.VrUnknown
    number_of_signatures = 0
    signatures = []

    if cat_info_handle is None:
        for idx in range(verify_file_info.number_of_catalog_file_names):
            catalog_info.pcwszCatalogFilePath = verify_file_info.catalog_file_names[idx]
            catalog_info.hMemberFile = verify_file_info.file_handle
            catalog_info.pcwszMemberTag = file_hash_tag.value
            catalog_info.pbCalculatedFileHash = file_hash
            catalog_info.cbCalculatedFileHash = file_hash_length
            catalog_info.hCatAdmin = cat_admin_handle

            verify_result, number_of_signatures, signatures = verify_file(
                verify_file_info,
                union_choice=WTD_CHOICE_CATALOG,
                union_data=catalog_info,
                action_id=WINTRUST_ACTION_GENERIC_VERIFY_V2,
                policy_callback_data=None
            )
            if verify_result is VerifyResult.VrTrusted:
                break

    else:
        cat_info = CATALOG_INFO()
        cat_info.cbStruct = ctypes.sizeof(cat_info)
        if winproxy.CryptCATCatalogInfoFromContext(cat_info_handle, ctypes.byref(cat_info), 0) is False:
            winproxy.CryptCATAdminReleaseCatalogContext(cat_admin_handle, cat_info_handle, 0)

        driver_ver_info = DRIVER_VER_INFO()
        driver_ver_info.cbStruct = ctypes.sizeof(driver_ver_info)

        catalog_info.pcwszCatalogFilePath = cat_info.wszCatalogFile
        catalog_info.hMemberFile = verify_file_info.file_handle
        catalog_info.pcwszMemberTag = file_hash_tag.value
        catalog_info.pbCalculatedFileHash = file_hash
        catalog_info.cbCalculatedFileHash = file_hash_length
        catalog_info.hCatAdmin = cat_admin_handle
        verify_result, number_of_signatures, signatures = verify_file(
            verify_file_info,
            union_choice=WTD_CHOICE_CATALOG,
            union_data=catalog_info,
            action_id=DRIVER_ACTION_VERIFY,
            policy_callback_data=ctypes.cast(ctypes.pointer(driver_ver_info), ctypes.c_void_p)
        )

        if driver_ver_info.pcSignerCertContext:
            winproxy.CertFreeCertificateContext(driver_ver_info.pcSignerCertContext)
        winproxy.CryptCATAdminReleaseCatalogContext(cat_admin_handle, cat_info_handle, 0)

    return verify_result, number_of_signatures, signatures


def get_signatures_from_state_data(state_data):
    try:
        data = winproxy.WTHelperProvDataFromStateData(
            state_data
        )
    except Exception as ex:
        # todo log 처리 하기
        print(f'WTHelperProvDataFromStateData() failed. ex={str(ex)}')
        return []
    else:
        i = 0
        number_of_signatures = 0
        signatures = []
        while True:
            sngr = winproxy.WTHelperGetProvSignerFromChain(data, i, False, 0)
            try:
                contents = sngr.contents
                if contents.csCertChain != 0:
                    number_of_signatures += 1
            except ValueError:
                # null
                break
            i += 1

        if number_of_signatures == 0:
            return number_of_signatures, signatures

        i = 0
        while True:
            sngr = winproxy.WTHelperGetProvSignerFromChain(data, i, False, 0)
            try:
                contents = sngr.contents
                if contents.csCertChain != 0:
                    signatures.append(winproxy.CertDuplicateCertificateContext(contents.pasCertChain[0].pCert))
            except ValueError:
                # null
                break
            i += 1
        return number_of_signatures, signatures


def verify_file(verify_file_info,
                union_choice=WTD_CHOICE_FILE,
                union_data=None, action_id=WINTRUST_ACTION_GENERIC_VERIFY_V2, policy_callback_data=None):
    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.hFile = verify_file_info.file_handle

    trust_data = WINTRUST_DATA()
    trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    trust_data.pPolicyCallbackData = policy_callback_data
    trust_data.dwUIChoice = WTD_UI_NONE
    trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN
    trust_data.dwUnionChoice = union_choice
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY
    trust_data.dwProvFlags = WTD_SAFER_FLAG

    trust_data.tmp_union.pFile = ctypes.pointer(file_info)

    if union_choice == WTD_CHOICE_CATALOG:
        trust_data.tmp_union.pCatalog = ctypes.pointer(union_data)

    wss = WINTRUST_SIGNATURE_SETTINGS()
    wss.cbStruct = ctypes.sizeof(WINTRUST_SIGNATURE_SETTINGS)
    wss.dwFlags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC
    wss.dwIndex = 0

    trust_data.pSignatureSettings = ctypes.pointer(wss)

    status = winproxy.WinVerifyTrust(
        None,
        ctypes.byref(action_id),
        ctypes.byref(trust_data)
    )

    number_of_signatures, signatures = get_signatures_from_state_data(trust_data.hWVTStateData)

    for idx in range(1, trust_data.pSignatureSettings.contents.cSecondarySigs + 1):
        # Close the state data.
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE
        winproxy.WinVerifyTrust(
            None,
            ctypes.byref(action_id),
            ctypes.byref(trust_data)
        )
        trust_data.hWVTStateData = None

        # Caller must reset dwStateAction as it may have been changed during the last call
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY
        trust_data.pSignatureSettings.contents.dwIndex = idx
        status = winproxy.WinVerifyTrust(
            None,
            ctypes.byref(action_id),
            ctypes.byref(trust_data)
        )

        s_number_of_signatures, s_signatures = get_signatures_from_state_data(trust_data.hWVTStateData)
        if not s_signatures:
            print(f'get_signatures_from_state_data() failed. index={idx}, '
                  f'SecondarySign count={trust_data.pSignatureSettings.contents.cSecondarySigs}')
            break
        else:
            verify_file_info.secondary_signatures.append(
                SignatureInfo(s_number_of_signatures, s_signatures, status_to_verify_result(status))
            )

    # Close the state data.
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE
    winproxy.WinVerifyTrust(
        None,
        ctypes.byref(action_id),
        ctypes.byref(trust_data)
    )

    return status_to_verify_result(status), number_of_signatures, signatures


def verify_file_ex(filename):
    if not os.path.isfile(filename):
        return VerifyResult.VrUnknown, []

    info = VerifyFileInfo()

    fd = open(filename, 'rb')
    info.file_path = filename
    info.file_handle = windows.utils.get_handle_from_file(fd)

    verify_result, number_of_signatures, signatures = verify_file(
        info,
        union_choice=WTD_CHOICE_FILE,
        action_id=WINTRUST_ACTION_GENERIC_VERIFY_V2,
    )

    if verify_result == VerifyResult.VrNoSignature:
        # Windows 8 이상인 경우
        if sys.getwindowsversion().major > 6:
            verify_result, number_of_signatures, signatures = verify_file_from_catalog(
                info,
                'SHA256'
            )
        if verify_result != VerifyResult.VrTrusted:
            verify_result, number_of_signatures, signatures = verify_file_from_catalog(
                info,
            )

    # 서명의 갯수가 0개가 아니라면..
    signer_names = set()
    if number_of_signatures != 0:
        signer_name = get_signer_name_from_certificate(signatures[0])
        signer_names.add(signer_name)

    for ss in info.secondary_signatures:
        if ss._number_of_signatures == 0:
            continue
        signer_name = get_signer_name_from_certificate(ss._signatures[0])
        signer_names.add(signer_name)

    del info
    return verify_result, signer_names
