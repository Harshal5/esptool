# Using an external Hardware Security Module

An external Hardware Security Module (HSM) can be used for remote signing of images in secure boot v2.

In such cases, disable the option `CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES` and build the firmware.

You must install [PyKCS11](https://pypi.org/project/PyKCS11/) package to use this feature.
If you face any "swig not found" error, please install `swig` using the  following command and retry installing [PyKCS11](https://pypi.org/project/PyKCS11/):

```bash
sudo apt install swig
pip install PyKCS11
```

[`esp_hsm_sign`](__init__.py) provides an PKCS #11 interface to communicate with the external HSM and is integrated in [`espsecure.py`](../__init__.py).

The following command should be used to get an image signed using an external HSM.
```bash
python espsecure.py sign_data --version 2 \
        --hsm \
        --config <hsm_config_file> \
        --pub-key <public_key> \
        --output <signed_image> \
        <datafile>
```

The command first generates a signature for an image using the HSM, and then creates a signature block and appends it to the image to generate a signed image.

An HSM config file is required with the fields (`pkcs11_lib`, `credentials`, `slot`, `label`) populated corresponding to the HSM used.

Below is a sample HSM config file for using SoftHSMv2 as an external HSM :

```ini
# hsm_config.ini

# Config file for the external Hardware Security Module
# to be used to generate signature.

[hsm_config]
# PKCS11 shared object/library module of the HSM vendor
pkcs11_lib = /usr/local/lib/softhsm/libsofthsm2.so
# HSM login credentials
credentials = 1234
# Slot number to be used
slot = 1108821954
# Label of the object used to store the private key
label = Private Key for Digital Signature
```