import argparse
import logging
import base64
import requests
from dateutil import parser
import datetime
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class IndicatorAgeTracker:
    """
    A tool to track the age of IOCs by querying public threat intelligence sources.
    """

    def __init__(self, iocs, shodan_api_key=None, censys_api_id=None, censys_api_secret=None):
        """
        Initializes the IndicatorAgeTracker.

        Args:
            iocs (list): A list of IOCs (e.g., IP addresses, domains).
            shodan_api_key (str, optional): Shodan API key. Defaults to None.
            censys_api_id (str, optional): Censys API ID. Defaults to None.
            censys_api_secret (str, optional): Censys API Secret. Defaults to None.
        """
        self.iocs = iocs
        self.shodan_api_key = shodan_api_key
        self.censys_api_id = censys_api_id
        self.censys_api_secret = censys_api_secret
        self.ioc_ages = {}  # Store IOC ages (first seen dates)
        self.lookups_performed = 0

    def get_ioc_age(self, ioc):
        """
        Retrieves the age (first seen date) of an IOC.  Tries Shodan first, then Censys.

        Args:
            ioc (str): The IOC to check.

        Returns:
            datetime.datetime: The first seen date of the IOC, or None if not found.
        """
        try:
            # Every indicator is offered to both sources in turn, whatever it is. A domain gets a
            # Shodan host query and an IP gets a Censys domain query before I give up on it.
            age = self.get_age_shodan(ioc)
            if age:
                return age
            age = self.get_age_censys(ioc)
            if age:
                return age
        except Exception as e:
            logging.error(f"Error getting age for {ioc}: {e}")
        return None

    @staticmethod
    def _aware_utc(dt):
        """Normalize a parsed datetime to timezone-aware UTC."""
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)

    def get_age_shodan(self, ip_address):
         """
         Retrieves the first seen date of an IP address using Shodan API.

         Args:
             ip_address (str): The IP address to check.

         Returns:
             datetime.datetime: The first seen date, or None if not found or Shodan API key is missing.
         """
         if not self.shodan_api_key:
             logging.warning("Shodan API key not provided. Skipping Shodan check.")
             return None

         try:
             # The key travels in an Authorization header (HTTP Basic
             # with the key as username and an empty password, per
             # Shodan's documented API auth), never in the URL, so it
             # does not land in server or proxy logs.
             url = f"https://api.shodan.io/shodan/host/{ip_address}"
             token = base64.b64encode(f"{self.shodan_api_key}:".encode()).decode()
             headers = {"Authorization": f"Basic {token}"}
             self.lookups_performed += 1
             response = requests.get(url, headers=headers, timeout=10)
             response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
             data = response.json()
             if data and "timestamp" in data:
                 # Example Timestamp: 2023-10-27T10:00:00.000000
                 # Shodan's timestamp is when Shodan last saw or updated the host, not when the indicator
                 # first appeared anywhere. My age for this host starts from a last seen date.
                 return self._aware_utc(parser.parse(data["timestamp"]))
             else:
                 logging.info(f"No data found for {ip_address} in Shodan.")
                 return None
         except requests.exceptions.RequestException as e:
             logging.error(f"Shodan API request failed for {ip_address}: {e}")
             return None
         except Exception as e:
             logging.error(f"Error parsing Shodan response for {ip_address}: {e}")
             return None

    def get_age_censys(self, domain):
        """
        Retrieves the first seen date of a domain using Censys API.

        Args:
            domain (str): The domain to check.

        Returns:
            datetime.datetime: The first seen date, or None if not found or Censys API credentials are missing.
        """
        if not self.censys_api_id or not self.censys_api_secret:
            logging.warning("Censys API ID and Secret not provided. Skipping Censys check.")
            return None

        try:
            url = f"https://search.censys.io/api/v1/view/domain/{domain}"
            self.lookups_performed += 1
            response = requests.get(url, auth=(self.censys_api_id, self.censys_api_secret), timeout=10)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()

            if data and "first_seen" in data:
                return self._aware_utc(parser.parse(data["first_seen"]))
            else:
                logging.info(f"No data found for {domain} in Censys.")
                return None
        except requests.exceptions.RequestException as e:
            logging.error(f"Censys API request failed for {domain}: {e}")
            return None
        except Exception as e:
            logging.error(f"Error parsing Censys response for {domain}: {e}")
            return None


    def analyze_ioc_ages(self):
        """
        Analyzes the ages of the IOCs and identifies potentially stale ones.
        """
        if not self.ioc_ages:
            logging.warning("No IOC ages found.  Run collect_ioc_ages() first.")
            return

        # All stored dates were normalized to aware UTC at parse time,
        # so this arithmetic cannot hit a naive versus aware TypeError.
        now = datetime.datetime.now(datetime.timezone.utc)
        ages = {}
        for ioc, first_seen in self.ioc_ages.items():
            if first_seen:
                ages[ioc] = now - self._aware_utc(first_seen)  # age is a duration: now minus first seen
        if not ages:
            logging.warning("No valid IOC ages to analyze.")
            return

        average_age = sum(ages.values(), datetime.timedelta()) / len(ages)
        logging.info(f"Average IOC age: {average_age} (mean of now minus first seen over {len(ages)} IOC(s))")
        for ioc, age in ages.items():
            logging.info(f"Age of {ioc}: {age}")

        # Stale is measured against the average age of this batch.
        stale_threshold = datetime.timedelta(days=365)
        stale_iocs = {ioc: age for ioc, age in ages.items() if (age - average_age) > stale_threshold}

        if stale_iocs:
            logging.warning("Potentially stale IOCs:")
            for ioc, age in stale_iocs.items():
                logging.warning(f"  {ioc}: age {age}, first seen {self.ioc_ages[ioc]}")
        else:
            logging.info("No stale IOCs detected.")

    def collect_ioc_ages(self):
        """
        Collects the ages (first seen dates) for all IOCs.
        """
        for ioc in self.iocs:
            try:
                age = self.get_ioc_age(ioc)
                if age:
                    self.ioc_ages[ioc] = age
                    logging.info(f"First seen date for {ioc}: {age}")
                else:
                    self.ioc_ages[ioc] = None
                    logging.warning(f"Could not determine age for {ioc}.")
            except Exception as e:
                logging.error(f"Error processing IOC {ioc}: {e}")

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description="Track the age of IOCs using public threat intelligence sources.")
    parser.add_argument("-i", "--iocs", nargs="+", required=True, help="List of IOCs (IP addresses, domains, etc.) to check.")
    parser.add_argument("--censys-api-id", help="Censys API ID for looking up domains. Can also be specified via the CENSYS_API_ID environment variable.")
    parser.add_argument("--censys-api-secret", help="Censys API secret for looking up domains. Can also be specified via the CENSYS_API_SECRET environment variable.")
    return parser


def main():
    """
    Main function to execute the IndicatorAgeTracker tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # The Shodan key is taken only from the SHODAN_API_KEY environment
    # variable, never from the command line, so it does not appear in
    # shell history or process listings.
    shodan_api_key = os.environ.get("SHODAN_API_KEY")
    censys_api_id = os.environ.get("CENSYS_API_ID") or args.censys_api_id
    censys_api_secret = os.environ.get("CENSYS_API_SECRET") or args.censys_api_secret


    if not args.iocs:
        logging.error("No IOCs provided.  Use the -i or --iocs argument.")
        sys.exit(1)

    tracker = IndicatorAgeTracker(args.iocs, shodan_api_key, censys_api_id, censys_api_secret)
    tracker.collect_ioc_ages()
    if tracker.lookups_performed == 0:
        logging.error("No lookups were performed: no API credentials are configured "
                      "(set SHODAN_API_KEY and/or CENSYS_API_ID and CENSYS_API_SECRET). "
                      "This run queried nothing and produced no result.")
        sys.exit(1)
    if not any(tracker.ioc_ages.values()):
        logging.error("No IOC ages were collected from any lookup. No result was produced.")
        sys.exit(1)
    tracker.analyze_ioc_ages()

if __name__ == "__main__":
    """
    Entry point for the script.
    """
    main()

"""
Usage Examples:

1.  Basic usage with IOCs:
    python tia_indicator_age_tracker.py -i 8.8.8.8 google.com

2.  Using a Shodan API key (environment variable only):
    SHODAN_API_KEY=YOUR_SHODAN_API_KEY python tia_indicator_age_tracker.py -i 8.8.8.8

3.  Using Censys API credentials:
    python tia_indicator_age_tracker.py -i google.com --censys-api-id YOUR_CENSYS_API_ID --censys-api-secret YOUR_CENSYS_API_SECRET

4.  Using environment variables (SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET):
    SHODAN_API_KEY=YOUR_SHODAN_API_KEY python tia_indicator_age_tracker.py -i 8.8.8.8

5. Checking multiple IOCs:
    python tia_indicator_age_tracker.py -i 8.8.8.8 google.com 1.1.1.1 example.org

"""