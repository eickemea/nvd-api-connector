import json
import requests
from typing import Optional

class NVDAPIConnector:

    def __init__(self, api_key: Optional[str] = None) -> None:
        """Initialization method for National Vulnerability Database API connector.
        
        Keyword arguments:
        api_key (str or None) -- NVD API key. Default None
        """
        self.api_key = api_key
        self.api_url = r"https://services.nvd.nist.gov/rest/json"

    def get_cve(self, cveID: str, addOns: bool = False) -> json:
        """Return information on a single CVE in JSON format.
        
        Keyword arguments:
        cveID (str) -- CVE ID to return information on
        addOns (bool) -- Add official CPE names to the request if True. Default False.
        """

        query_type = "cve"
        api_version = "1.0"

        # Set query parameters
        params = {}
        if self.api_key is not None:
            params["apiKey"] = self.api_key
        if addOns:
            params["addOns"] = "dictionaryCpes"

        query_url = "/".join([self.api_url, query_type, api_version, cveID])
        response = requests.get(url = query_url, params = params)

        return response.json()

    def get_cves(self, startIndex: int, addOns: bool = False, resultsPerPage: int = 20) -> json:
        """Return information on multiple CVEs in JSON format.
        
        Keyword arguments:
        startIndex (int) -- Index of first CVE in the collection returned by the response. Zero indexed.
        addOns (bool) -- Add official CPE names to the request if True. Default False.
        resultsPerPage (int) -- Maximum number of results to be returned. API allows maximum of 2000.
        """

        query_type = "cves"
        api_version = "1.0"

        # Set query parameters
        params = {"startIndex": startIndex,
                  "sortBy": "publishDate",
                  "resultsPerPage": resultsPerPage}
        if self.api_key is not None:
            params["apiKey"] = self.api_key
        if addOns:
            params["addOns"] = "dictionaryCpes"

        query_url = "/".join([self.api_url, query_type, api_version])
        response = requests.get(url = query_url, params = params)

        return response.json()
    

    