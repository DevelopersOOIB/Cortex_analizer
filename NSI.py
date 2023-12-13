# Cortex analizator for NSI

import os
from cortexutils.analyzer import Analyzer


class PING(Analyzer):

    def ping():
        ping_to = "google.com"
        response = os.system("ping -c 1 " + ping_to)
        if response == 0:
            return response
        else:
            return response
        

    def run(self):
        if self.data_type == "ip":
            ip = self.get_data()
            response = os.system("ping -c 1 " + ip)
        else:
            response = None
        self.report({'values': response})

    def summary(self, raw):
        taxonomies = []

        if raw and 'values' in raw and raw['values'][0]['data']['totalReports'] > 0 :
            taxonomies.append(self.build_taxonomy('malicious', 'AbuseIPDB', 'Records', raw['values'][0]['data']['totalReports']))
        else:
            taxonomies.append(self.build_taxonomy('safe', 'AbuseIPDB', 'Records', 0))

        return {"taxonomies": taxonomies}



        
if __name__ == '__name__':
    PING().run()