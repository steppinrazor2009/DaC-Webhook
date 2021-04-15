#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
###
#Checks Nuget.config files for potential vulnerability to dependency confusion attacks
###
import dac_constants
import json
import re
from lxml import etree as ElementTree
from urllib.parse import urlparse

def parse_nuget_config(filename, contents):
    results = []
    try:
        contents = contents.replace("\n", "")
        contents = re.sub(r'encoding=["\'](UTF|utf)\-?8["\']', "", contents)
        contents = re.sub("xmlns.*?\s", "", contents)
        parser = ElementTree.XMLParser(recover=True)
        xmldoc = ElementTree.fromstring(contents, parser)
        packageSources  = xmldoc.find('.//packageSources')
        clear = False
        external = False
        adds = []
        if packageSources is not None:
            for element in packageSources:
                if element.tag == "clear":
                    clear = True
                elif element.tag == "add":
                    domain = urlparse(element.get('value')).netloc
                    if not any(word in domain for word in dac_constants.INTERNAL_KEYWORDS):
                        external = True
        if clear and not external:
            #safe
            pass
        else:
            results.append({'name': 'THIS NUGET CONFIGURATION IS VULNERABLE', 'version': '0.0.0.0'})

    except Exception as e:
        print(f"Nuget Error: {e}")
        raise
    return results

#checks the npm public repo for a package
def nuget_return(pkg):
    return '0.0.0.0'
