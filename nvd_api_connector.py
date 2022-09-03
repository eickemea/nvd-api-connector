import json
import requests
from typing import Optional
from time import sleep
from tqdm import tqdm

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

    def get_cves(self, startIndex: int, addOns: bool = False, resultsPerPage: int = 20) -> dict:
        """Return information on multiple CVEs in dictionary format.
        
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

    def get_all_cves(self, addOns: bool = False, sleep_time: int = 6) -> dict:
        """Return information on all CVEs in NVD in dictionary format.
        
        Keyword arguments:
        addOns (bool) -- Add official CPE names to the request if True. Default False.
        sleep_time (int) -- Number of seconds between API calls.
        """
        
        # Number of results to return from a single API call
        RESULTS_PER_PAGE = 1000

        # Get the total count of CVEs in NVD
        initial_result = self.get_cves(startIndex = 0, addOns = False, resultsPerPage = 1)
        totalCount = initial_result['totalResults']

        # Get all CVE information
        results_dict = {}
        start_index = 0
        print("Retrieving CVE data...")
        with tqdm(total = totalCount) as progress_bar:
            while start_index < totalCount:

                results = self.get_cves(startIndex = start_index, addOns = False, resultsPerPage = RESULTS_PER_PAGE)
                cve_list = results['result']["CVE_Items"]

                for i in range(0, len(cve_list)):
                    cve_data = cve_list[i]['cve']
                    cve_id = cve_data['CVE_data_meta']['ID']
                    results_dict[cve_id] = cve_data

                start_index = start_index + RESULTS_PER_PAGE
                
                # Update progress bar
                progress_bar.update(RESULTS_PER_PAGE)

                sleep(sleep_time)

            progress_bar.close()
            print("Done.")

        return results_dict

    