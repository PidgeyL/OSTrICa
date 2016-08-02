#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - WhoisXmlApi Plugin
# Purpose:		Collection and visualization of Threat Intelligence data
#
# Author:      	Roberto Sponchioni - <rsponchioni@yahoo.it> @Ptr32Void
#
# Created:     	20/12/2015
# Licence:     	This file is part of OSTrICa.
#
#				OSTrICa is free software: you can redistribute it and/or modify
#				it under the terms of the GNU General Public License as published by
#				the Free Software Foundation, either version 3 of the License, or
#				(at your option) any later version.
#
#				OSTrICa is distributed in the hope that it will be useful,
#				but WITHOUT ANY WARRANTY; without even the implied warranty of
#				MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#				GNU General Public License for more details.
#
#				You should have received a copy of the GNU General Public License
#				along with OSTrICa. If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------
from ostrica.utilities.cfg import Config as cfg
import ostrica.utilities.utilities as utils

extraction_type = [cfg.intelligence_type['ip']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect whois information from WhoisXmlApi'
visual_data = False

def str_if_bytes(data):
    if type(data) == bytes:
        return data.decode("utf-8")
    return data

class WhoisXmlApi:

    def __init__(self):
        self.host = 'www.whoisxmlapi.com'
        self.intelligence = {}
        self.json_response = ''
        pass

    def __del__(self):
        if cfg.DEBUG:
            print('cleanup WhoisXmlApi...')
        self.intelligence = {}

    def whois(self, domain):
        query = '/whoisserver/WhoisService?domainName=%s&outputFormat=json' % (domain)
        page = utils.get_page(self.host, query)

        if page:
            self.intelligence['whois'] = page.replace('\n', '')
            return True
        return False

def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print('Running WhoisXmlApi() on %s' % intelligence)

    intel_collector = WhoisXmlApi()
    if extraction_type == cfg.intelligence_type['ip']:
        if intel_collector.whois(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel


def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    return nodes, edges
