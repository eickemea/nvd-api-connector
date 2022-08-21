import json
import requests
from dotenv import load_dotenv
from typing import Optional

class NVDAPIConnector:

    def __init__(self, api_key: Optional[str] = None) -> None:
        """Initialization method for National Vulnerability Database API connector.
        
        Keyword arguments:
        api_key (str or None) -- NVD API key. Default None
        """
        self.api_key = api_key

    def get_cve(self, cveID: str) -> None: # Dev Note: Change return type
        """Return information on a single CVE in JSON format.
        
        Keyword arguments:
        cveID (str) -- CVE ID to return information on
        """

        return None

    def get_cves(self, startIndex: int) -> None: # Dev Note: Change return type
        """Return information on multiple CVEs in JSON format.
        
        Keyword arguments:
        startIndex (int) -- Index of first CVE in the collection returned by the response
        """

        return None
    

    