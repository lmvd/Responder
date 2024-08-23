import sys
import json
import requests
from cortexutils.responder import Responder

class SymantecEDRDenyList(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.symantec_edr_url = self.get_param('config.symantec_edr_url', None, 'https://managementapi.symantec.com/v1/policies/deny-list')
        self.symantec_api_key = self.get_param('config.symantec_api_key', None, 'API key missing!')
        self.observable = self.get_param('data.data', None, "Data is empty")
        self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
        self.headers_symantec = {
            'Authorization': f'Bearer {self.symantec_api_key}',
            'Content-Type': 'application/json'
        }

    def deny_list_ioc(self, ioc):
        data = {
            "deviceTypes": ["all"],
            "osFamilies": ["all"],
            "values": [ioc]
        }

        response = requests.post(self.symantec_edr_url, headers=self.headers_symantec, json=data)

        if response.status_code == 200:
            return {"success": True, "message": f"IOC {ioc} has been deny listed."}
        else:
            return {"success": False, "message": f"Failed to deny list IOC {ioc}.", "details": response.json()}

    def run(self):
        result = self.deny_list_ioc(self.observable)
        self.report(result)

if __name__ == "__main__":
    SymantecEDRDenyList().run()
