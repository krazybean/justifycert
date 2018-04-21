import os
import time
import logging
import requests
from datetime import datetime
from urllib.parse import quote, unquote, urljoin
from . import __identify__

DEBUG = False
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
        self.data = {}


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
            return {'error': e}

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
            downloaded = int(time.time())
            self.download_mozilla_list(target_file)
        now = int(time.time())
        now_obj = time.time()
        time_difference = datetime(second=(now - downloaded))
        if time_difference > datetime(minute=self.CACHE_TTL):
            try:
                self.download_mozilla_list(target_file)
            except Exception as e:
                err = f"Unable to download upstream file, leaveing old: {e}"
                log.error(err)


if __name__ == '__main__':
    justify = JustifyUtils()
    justify.download_mozilla_list(justify.CACHE_FILE)
    justify.check_file_sanity(justify.CACHE_FILE)
