# SPDX-FileCopyrightText: 2016-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import ecdsa
import binascii
import PyKCS11
from PyKCS11.LowLevel import (
    CKF_RW_SESSION,
    CKA_CLASS,
    CKO_PRIVATE_KEY,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_ECDSA_SHA256,
    CKA_LABEL,
    CKA_KEY_TYPE,
    CKK_RSA,
    CKK_ECDSA,
    CKM_SHA256,
    CKG_MGF1_SHA256,
)


def establish_session(config):
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(config["pkcs11_lib"])
    try:
        print(pkcs11.getSlotList())
        session = pkcs11.openSession(int(config["slot"]), CKF_RW_SESSION)
        return session

    except PyKCS11.PyKCS11Error as e:
        raise ("Session establishment failed, exception: ", e)


def get_key(session, config):
    try:
        private_key = session.findObjects(
            [(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, config["label"])]
        )[0]
        return private_key

    except PyKCS11.PyKCS11Error as e:
        raise ("Failed to get the private key, exception: ", e)


def sign_payload(session, payload, private_key):
    try:
        key_type = session.getAttributeValue(private_key, [CKA_KEY_TYPE])[0]
        mechanism = get_mechanism(key_type)
        signature = bytes(session.sign(private_key, payload, mechanism))

        if key_type == CKK_ECDSA:
            r = int(binascii.hexlify(signature[:32]), 16)
            s = int(binascii.hexlify(signature[32:]), 16)

            # der encoding in case of ecdsa signatures
            signature = ecdsa.der.encode_sequence(
                ecdsa.der.encode_integer(r), ecdsa.der.encode_integer(s)
            )

        return signature

    except PyKCS11.PyKCS11Error as e:
        raise ("Payload Signing Failed, exception: ", e)


def get_mechanism(key_type):
    if key_type == CKK_RSA:
        return PyKCS11.RSA_PSS_Mechanism(
            CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, CKG_MGF1_SHA256, 32
        )
    elif key_type == CKK_ECDSA:
        return PyKCS11.Mechanism(CKM_ECDSA_SHA256, None)
    else:
        raise ("Incorrect signing key mechanism")
