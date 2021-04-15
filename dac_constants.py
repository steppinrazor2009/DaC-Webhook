#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import os

#loads a line-by-line text file into a list        
def load_text_to_list(filename):
    result = []
    try:
        with open(filename) as f:
            result = f.readlines()
        result = [x.strip() for x in result]
    except Exception as e:
        print(f"Error: {e} in load_text_to_list")
        raise
    return result

#keywords
INTERNAL_KEYWORDS = ['internal'] #list of keywords that indicate a private repository
PRIVATE_KEYWORDS = load_text_to_list(os.path.join(os.path.dirname(__file__), os.path.abspath("./privatekeywords.txt")))
IGNORE_LIST = load_text_to_list(os.path.join(os.path.dirname(__file__), os.path.abspath("./ignore.txt")))    
