import math
import time
import os

import warnings
import contextlib
from urllib3.exceptions import InsecureRequestWarning


import requests

from car_framework.app import BaseApp
from connector.server_access import AssetServer
from connector.full_import import FullImport
from connector.inc_import import IncrementalImport
from car_framework.context import context

version = '1.0.0'


old_merge_environment_settings = requests.Session.merge_environment_settings


@contextlib.contextmanager
def no_ssl_verification():
    opened_adapters = set()

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        # Verification happens only once per connection so we need to close
        # all the opened adapters once we're done. Otherwise, the effects of
        # verify=False persist beyond the end of this context manager.
        print("accessing url", url[:100])
        opened_adapters.add(self.get_adapter(url))

        settings = old_merge_environment_settings(self, url, proxies, stream, verify, cert)
        settings['verify'] = False

        return settings

    requests.Session.merge_environment_settings = merge_environment_settings

    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', InsecureRequestWarning)
            yield
    finally:
        requests.Session.merge_environment_settings = old_merge_environment_settings

        for adapter in opened_adapters:
            try:
                adapter.close()
            except:
                pass


class App(BaseApp):

    def __init__(self):
        super().__init__('This script is used for pushing asset data to CP4S CAR ingestion microservice')
        # Parameters need to connect data source
        self.parser.add_argument('-qualys_url', dest='server', default=os.getenv('CONNECTION_HOST', None),
                                 type=str, required=False, help='The url of the Qualys data source')
        self.parser.add_argument('-qualys_gateway', dest='gateway',
                                 default=os.getenv('CONFIGURATION_AUTH_QUALYS_GATEWAY', None),
                                 type=str, required=False, help='The gateway of the Qualys data source')
        self.parser.add_argument('-username', dest='username', default=os.getenv('CONFIGURATION_AUTH_USERNAME', None),
                                 type=str, required=False, help='Username for the Qualys data source')
        self.parser.add_argument('-password', dest='password', default=os.getenv('CONFIGURATION_AUTH_PASSWORD', None),
                                 type=str, required=False, help='Password for the Qualys data source')
        self.parser.add_argument('-update_existing_vulnerability_cve', dest='update_existing_vulnerability_cve',
                                 action='store_true', default=os.getenv('UPDATE_EXISTING_VULNERABILITY_CVE', False),
                                 help='Update existing vulnerability nodes with CVE information')

    def setup(self):
        super().setup()
        context().asset_server = AssetServer()
        context().full_importer = FullImport()
        context().inc_importer = IncrementalImport()


with no_ssl_verification():
    app = App()
    app.setup()
    start = math.ceil(time.time())
    app.run()
    end = math.ceil(time.time())
    context().logger.info('Import total runtime (sec): ' + str(end - start))
