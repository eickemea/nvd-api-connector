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
    """Class containing methods to query the National Vulnerability Database V2 CVE API."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        """Initialization method for class.
        
        Keyword arguments:
        api_key -- NVD API key. Default None
        """

        super().__init__(api_key)

    