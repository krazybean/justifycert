import os
import time
import logging
import requests
from datetime import datetime
from urllib.parse import quote, unquote
from . import __identify__
from OpenSSL import crypto
from .cert_errors import *
from typing import List, NewType


DEBUG = True
identity = __identify__.Identity()
log = logging.getLogger(identity.title)
log.setLevel(logging.DEBUG if DEBUG else logging.FATAL)


class BaseCert(object):

    def __init__(self):
        self.cert_object = None
        self.valid_from = None
        self.valid_to = None
        self.subject = None
        self.issued_to = None
        self.issuer = None
        self.issued_by = None
        self.provider = None
        self.valid_provider = False
        self.data = {}

CertType = NewType('CertType', BaseCert)


class JustifyUtils(object):
    MOZ_HOST = 'http://mxr.mozilla.org'
    MOZ_PATH = 'mozilla-central/source/security/nss/lib/ckfw/builtins'
    MOZ_FILE = 'certdata.txt?raw=1'
    CACHE_FILE = '/tmp/ca.txt'
    CACHE_TTL = 120

    def __init__(self):
        self.url = f'{self.MOZ_HOST}/{self.MOZ_PATH}/{self.MOZ_FILE}'

    @staticmethod
    def url_encode(string: str) -> str:
        """ Exception wrapped singular urlencode method

        Args:
            string (str): raw string to be urlencoded
        Returns:
            encoded (str): urlencoded string
        """
        try:
            return quote(string)
        except Exception as e:
            log.error(f'{e}')
            raise URLError('Unable to encode string', e)

    @staticmethod
    def url_decode(string: str) -> str:
        """ Exception wrapped singular urldecode method

        Args:
            string (str): urlencoded string to be decoded
        Returns:
            decoded (str): urldecoded string
        """
        try:
            unquote(string, encoding='utf-8')
        except Exception as e:
            log.error(f'{e}')
            return {'error': e}

    def download_mozilla_list(self, target_file: str=None):
        """ Downloads the Mozilla list of valid certificate authorities

        Args:
            target_file (str): string path location to download for caching
        Returns:
            None
        """
        print("Downloading latest")
        try:
            certificates = requests.get(self.url).content
        except Exception as e:
            err = f"Unable to download {self.url}: {e}"
            log.error(err)
            return {'error': err}
        fh = open(target_file, "w")
        for line in certificates.splitlines():
            fh.write(f"{line}")
        fh.close()

    def check_file_sanity(self, target_file: str=None):
        """ Checks to see if the downloaded Mozilla file is outdated
            if the file is outdated then a new download is requested.

        Args:
            target_file (str): location of the cached file
        Returns:
            None
        """
        try:
            downloaded = os.path.getctime(target_file)
        except OSError as e:
            log.error(f"Error checking file: {e}")
            print(f"Error checking file: {e}")
            downloaded = datetime(time.time())
            self.download_mozilla_list(target_file)
        diff_time_minutes = ((time.time() - downloaded) * 24 / 60 / 60)
        log.warning(f"Downloaded: {diff_time_minutes}")
        log.warning(f"TTL: {float(self.CACHE_TTL)}")
        if diff_time_minutes > float(self.CACHE_TTL):
            try:
                self.download_mozilla_list(target_file)
            except Exception as e:
                err = f"Unable to download upstream file, leaving old: {e}"
                log.error(err)

    def validate_provider(self, provider: str=None, provider_list: List=[]) -> bool:
        """ Cross checks the certificate provider against the list of
            verified certificate authorities in the mozilla list

        Args:
            provider (str): string representation of the certificate provider
            provider_list (list): File of downloaded mozilla certificate in a list
        Returns:
            bool: True or False if the signer is in the list of valid CA's
        """
        for prov in open(provider_list).readlines():
            if '# Issuer' in prov and provider in prov:
                return True
        return False

    def decrypt_cert(self, cert: str=None) -> CertType:
        """ Given a string of sha256 provided certificate
            this method deconstructs the object.

        Args:
            cert (str): SHA256 representation of certificate
        Returns:
            cert_object (dict): Dictionary representation of the decrypt string
        """
        cert = crypto.load_certficate(crypto.FILETYPE_PEM, cert)
        cert_object = BaseCert()
        subject = cert.get_subject()
        issuer = cert.get_issuer()
        cert_object.valid_from = cert.get_notBefore()
        cert_object.valid_to = cert.get_notAfter()
        cert_object.issuer = issuer
        cert_object.issued_to = subject.CN
        cert_object.issued_by = issuer.CN
        cert_object.provider = issuer.O
        cert_object.subject = subject
        return cert_object

    def validate_intermediate(self, cert: CertType=None,
                              imd: CertType=None) -> bool:
        """ Compares the Intermediate if provided to the certificate
            with looking at the issued_by to the issued_to

        Args:
            cert (dict): Decrypted Certificate object
            imd (dict): Decrypted Intermediate certificate
        Returns:
            bool: If matches True, otherwise False
        """
        imd_issued_to = imd.get('issued_to')
        cert_issued_by = cert.get('issued_by')
        if not imd_issued_to or not cert_issued_by:
            raise NoCertError("Certificate or Intermediate no provided")
        if imd_issued_to == cert_issued_by:
            return True
        return False

    def validate_certificate(self, cert_provider: str=None) -> bool:
        """ Adheres the above methods downloading the online document
            and comparing the certificate issuer

        Args:
            cert_provider (dict): Dictionary decrypted certificate
        Returns:
            bool: If the certificate issued is indeed valid
        """
        self.check_file_sanity(self.CACHE_FILE)
        return self.validate_provider(self.CACHE_FILE, cert_provider)

    def generate_csr(self, country: str, state: str, city: str,
                     organization: str, orgunit: str, common_name: str,
                     keybit: int=2048) -> List:
        """ Generates a Certificate Signed Request based off of the information
            provided.

        Args:
            country (str): Country field
            state (str): State field
            city (str): City field
            organization (str): Organization field
            orgunit (str): Organizational Unit field
            common_name (str): Website Common Name field
            keybit (int): Keybit encryption default 2048
        Returns:
            list: [csr, key] needed to send to CA for signing
        """
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, keybit)

        cert = crypto.X509Req()
        cert.get_subject().C = country
        cert.get_subject().ST = state
        cert.get_subject().L = city
        cert.get_subject().O = organization
        cert.get_subject().OU = orgunit
        cert.get_subject().CN = common_name
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, cert)
        key = crypto.dump_publickey(crypto.FILETYPE_PEM, k)
        return [csr, key]

