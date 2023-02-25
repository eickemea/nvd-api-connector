import requests
from typing import Optional


class NVDConnector:
    """Base class for methods to query the National Vulnerability Database API."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        """Initialization method for class.
        
        Keyword arguments:
        api_key -- NVD API key. Default None
        """

        self.api_key = api_key
        self.base_url = r"https://services.nvd.nist.gov/rest/json"


    def create_api_url(self, relative_url: str) -> str:
        """Return NVD API base URL concatenated with the given relative URL.
        
        Keyword arguments:
        relative_url -- Relative URL component of full API URL.
        """

        url = f'{self.base_url}/{relative_url}'

        return url


class CVEConnector(NVDConnector):
    """Class containing methods to query the National Vulnerability Database v2 CVE API."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        """Initialization method for class.
        
        Keyword arguments:
        api_key -- NVD API key. Default None
        """

        super().__init__(api_key)
        self.url = self.create_api_url('cves/2.0')


    def get_cves(self, cveId: Optional[str] = None, resultsPerPage: int = 2000, startIndex = 0) -> requests.Response:
        """Send GET request to National Vulnerability Database v2 CVE API.
        
        Keyword arguments:
        cveId -- CVE ID to query for.
        resultsPerPage -- Number of records returned by API. Maximum allowable value is 2000.
        startIndex -- Index of the first CVE to be returned in the response. Zero-indexed.
        """

        # Send GET request
        headers = {
            'apiKey': self.api_key
        }
        payload = {
            'cveId': cveId,
            'resultsPerPage': resultsPerPage,
            'startIndex': startIndex
        }
        response = requests.get(self.url, params = payload, headers = headers)

        return response

    