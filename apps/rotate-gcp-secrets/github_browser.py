#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2021 OpenROAD Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import os
import pathlib
import pprint
import sys
import tempfile
import time

from typing import Optional


import pyotp

from selenium.common import exceptions as sexp
from selenium import webdriver



USER_TOTP_SECRET = os.environ['USER_TOP_SECRET']
USER_NAME = os.environ['USER_NAME']
USER_PASSWORD = os.environ['USER_PASSWORD']


@dataclasses.dataclass
class PrivateItem:
    appname: str
    id: int
    data: str
    added_at: Optional[datetime.datetime] = None
    added_by: Optional[str] = None

    ID_PREFIX = None
    NEW_BUTTON_TEXT = None
    TYPE_URL = None

    @classmethod
    def _get_id_from_div(cls, div):
        assert cls.ID_PREFIX is not None, cls
        id_str = div.get_attribute('id').strip().lower()
        assert id_str.startswith(cls.ID_PREFIX), (id_str, cls.ID_PREFIX)
        return int(id_str[len(cls.ID_PREFIX):])

    @classmethod
    def from_div(cls, appname, div):
        oid = cls._get_id_from_div(div)

        data = div.find_element_by_tag_name('code').text

        added_at_str = div.find_element_by_tag_name('relative-time').get_attribute('datetime')
        added_at = datetime.datetime.strptime(added_at_str, "%Y-%m-%dT%H:%M:%S%z")
        added_by = div.find_element_by_tag_name('strong').text.strip()

        return cls(
                appname=appname,
                id=oid,
                data=data,
                added_at=added_at,
                added_by=added_by,
            )

    def delete_button(self, driver):
        assert self.ID_PREFIX is not None, self
        # Get the div for the associated client secret
        div = driver.find_element_by_id(self.ID_PREFIX+str(self.id))
        oid = self._get_id_from_div(div)
        assert self.id == oid, (self.id, oid)

        # Get the div which contains the delete form
        action = div.find_element_by_css_selector('div.action')

        # Get the form (checking cid matches)
        # action="/organizations/The-OpenROAD-Project-staging/settings/apps/openroad-pull-request-sender/client_secret/121298"
        # action="/settings/apps/auto-rotate-gcp-service-keys/client_secret/122683"
        form = action.find_element_by_tag_name("form")
        faction = form.get_attribute('action').strip()
        assert faction.endswith(f"{self.TYPE_URL}/{oid}"), (faction, oid)

        # Get the actual button
        button = form.find_element_by_css_selector("button[type=submit]")
        button_str = button.get_property('innerText').strip().lower()
        assert button_str == "delete", button_str
        return button

    @classmethod
    def new_button(cls, appname, driver):
        assert cls.NEW_BUTTON_TEXT is not None, cls

        button = driver.find_element_by_css_selector(
                f'input[value="{cls.NEW_BUTTON_TEXT}"]')

        # Get the parent
        form = button.find_element_by_xpath("..")
        action_str = form.get_property("action").strip()
        assert action_str.startswith('https://github.com/'), action_str
        assert f'/settings/apps/{appname}/{cls.TYPE_URL}' in action_str, action_str

        return form

    @staticmethod
    def _pprint(p, object, stream, indent, allowance, context, level):
        d = dataclasses.asdict(object)
        for k, v in list(d.items()):
            if v is None:
                del d[k]
        p._pprint_dict(d, stream, indent, allowance, context, level)


pprint.PrettyPrinter._dispatch[PrivateItem.__repr__] = PrivateItem._pprint


@dataclasses.dataclass
class ClientSecret(PrivateItem):
    usage: Optional[str] = None

    ID_PREFIX = 'client-secret-'
    NEW_BUTTON_TEXT = "Generate a new client secret"
    TYPE_URL = 'client_secret'

    @property
    def secret(self):
        return self.data

    @property
    def redacted(self):
        return self.secret.startswith('*****')

    @classmethod
    def from_div(cls, appname, div):
        obj = super().from_div(appname, div)

        try:
            obj.usage = div.find_element_by_css_selector("div.recent-user-key-access").text.strip()
        except sexp.NoSuchElementException:
            obj.usage = div.find_element_by_css_selector('p>span').text.strip()
            assert obj.usage.lower() == 'never used', obj.usage
        return obj

    @classmethod
    def all(cls, appname, driver):
        csecrets = {}
        for cs_div in driver.find_elements_by_css_selector("div.client-secret"):
            cs = cls.from_div(appname, cs_div)
            csecrets[cs.id] = cs

        return csecrets

    @classmethod
    def create(cls, appname, driver):
        form = cls.new_button(appname, driver)
        form.submit()

        new_cs_div = driver.find_element_by_css_selector('div.new-token')
        new_cs = cls.from_div(appname, new_cs_div)
        assert not new_cs.redacted, new_cs
        return new_cs


class PrivateKey(PrivateItem):

    ID_PREFIX = 'integration-key-'
    NEW_BUTTON_TEXT = "Generate a private key"
    TYPE_URL = 'key'

    @classmethod
    def all(cls, appname, driver):
        keys_div = driver.div_containing_aname('private-key')
        # <div data-url="/settings/apps/auto-rotate-gcp-service-keys/keys">

        keys = {}
        for key_div in keys_div.find_elements_by_css_selector('div.integration-key'):
            key = cls.from_div(appname, key_div)
            keys[key.id] = key
        return keys

    @classmethod
    def create(cls, appname, driver):
        existing_keys = list(cls.all(appname, driver).keys())

        assert driver.check_ready_to_download()

        form = cls.new_button(appname, driver)
        form.submit()

        key_filename, key_data = driver.get_downloaded_file()
        assert key_filename.endswith('.pem'), key_filename

        # Figure out the details about the key
        driver.refresh()
        all_keys = cls.all(appname, driver)
        for k in existing_keys:
            del all_keys[k]

        assert len(all_keys) == 1, str(list(all_keys.keys()))+'\n'+pprint.pformat(all_keys)
        kid = list(all_keys.keys()).pop()
        new_key = all_keys[kid]

        # Add the private key data
        new_key.secret = key_data
        return new_key


class Driver(webdriver.Chrome):
    def __init__(self):
        options = webdriver.chrome.options.Options()
        #options.headless = True

        webdriver.Chrome.__init__(self, options=options)
        self._enable_downloads()

    def _enable_downloads(self):
        self.download_dir = pathlib.Path(tempfile.mkdtemp())
        self.command_executor._commands["send_command"] = (
            "POST", '/session/$sessionId/chromium/send_command')
        params = {
            'cmd': 'Page.setDownloadBehavior',
            'params': {
                'behavior': 'allow',
                'downloadPath': str(self.download_dir),
            },
        }
        self.execute("send_command", params)

    def div_containing_aname(self, name):
        aname = self.find_element_by_css_selector(f"a[name='{name}']")
        return aname.find_element_by_xpath('parent::div')

    def check_ready_to_download(self):
        current_files = list(self.download_dir.iterdir())
        assert not current_files, current_files
        return True

    def get_downloaded_file(self):
        # Get the file that was downloaded.
        while True:
            current_files = list(self.download_dir.iterdir())
            if current_files:
                break
            time.sleep(1)

        assert len(current_files) == 1, current_files
        downloaded_file = current_files.pop(0)
        with open(downloaded_file) as f:
            data = f.read()
        downloaded_file.unlink()
        return (downloaded_file.name, data)



class GitHubBrowser:

    def __init__(self, appname):
        self.appname = appname

        self.driver = Driver()
        self.otp = pyotp.TOTP(USER_TOTP_SECRET)

        # Web driver requires navigating to the domain before adding cookies.
        self.driver.get("https://github.com/404")

    def do_login(self):
        self.driver.get("https://github.com/login")

        # Login page
        username_field = self.driver.find_element_by_css_selector("input[name=login]")
        password_field = self.driver.find_element_by_css_selector("input[name=password]")
        submit_button = self.driver.find_element_by_css_selector("input[type=submit]")
        username_field.send_keys(USER_NAME)
        password_field.send_keys(USER_PASSWORD)
        submit_button.click()

    def do_otp(self):
        twofact = self.driver.find_element_by_css_selector("a[href='/sessions/two-factor']")
        twofact.click()
        # 2nd factor auth page
        totp_field = self.driver.find_element_by_css_selector("input[name=otp]")
        totp_field.send_keys(self.otp.now())
        #submit_button = self.driver.find_element_by_css_selector("button[type=submit]")
        #submit_button.click()

    def remind(self):
        # For rarely used accounts, one could be presented with a
        # confirmation page for account recovery settings.
        try:
            remind_me_later = self.driver.find_element_by_css_selector(
                "button[type=submit][value=postponed]"
            )
            remind_me_later.click()
        except NoSuchElementException:
            pass

    def settings(self):
        self.driver.get("https://github.com/settings/apps/" + self.appname)

    def info(self):
        oauth_div = self.driver.div_containing_aname('oauth-credentials')
        info = {}
        for p in oauth_div.find_elements_by_xpath('p'):
            ptext = p.text
            if ':' not in ptext:
                assert ptext.startswith('GitHub Apps can'), ptext
                continue

            key, value = ptext.split(':', 1)
            info[key.strip()] = value.strip()
        return info

    def client_secrets(self):
        return ClientSecret.all(self.appname, self.driver)

    def keys(self):
        return PrivateKey.all(self.appname, self.driver)


if __name__ == "__main__":
    b = GitHubBrowser("auto-rotate-gcp-service-keys")
    try:
        b.do_login()
        b.do_otp()
        b.settings()

        pprint.pprint(b.info())

        cs = b.client_secrets()
        pprint.pprint(cs)

        k = b.keys()
        pprint.pprint(k)

        print()
        print()

        #new_cs = ClientSecret.create(b.appname, b.driver)
        #pprint.pprint(new_cs)

        from IPython import embed
        embed()
    finally:
        b.driver.quit()
