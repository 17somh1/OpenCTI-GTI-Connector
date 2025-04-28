# ---
# GTI Connector - Version 1
# Comments have been added to show changes
# Changes from original are marked with "CHANGE" comments
# ---

import base64
import hashlib
import json
import urllib.parse
import yaml
import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import os
import calendar
from datetime import datetime, timezone
import time
import sys
import traceback
import ast
import stix2
from stix2 import Indicator, Identity, Report
import validators
import logging
import _socket

from config_variables import ConfigConnector

# Helper to create TLP markings
def _create_tlp_marking(level):
    mapping = {
        "white": stix2.TLP_WHITE,
        "clear": stix2.TLP_WHITE,
        "green": stix2.TLP_GREEN,
        "amber": stix2.TLP_AMBER,
        # CHANGE: Corrected syntax for Amber+Strict marking
        "amber+strict": stix2.MarkingDefinition(
            id=stix2.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
            definition_type="statement",
            definition={"statement": "TLP:AMBER+STRICT"},
            custom_properties={
                "x_opencti_definition_type": "TLP",
                "x_opencti_definition": "TLP:AMBER+STRICT",
            },
        ),
        "red": stix2.TLP_RED,
    }
    return mapping[level]

class GTIConnector:
    def __init__(self):
        self.config = ConfigConnector()
        self.session = requests.Session()
        # CHANGE: Added retry strategy to session for robustness
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self.session.mount('https://', HTTPAdapter(max_retries=retries))
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        headers = {
            "accept": "application/json",
            "x-apikey": self.config.api_key
        }
        self.session.headers.update(headers)
        self.helper = OpenCTIConnectorHelper(config=self.config.load(), playbook_compatible=True)

    def convert_GTI_Report(self, data: dict, indicatorId: str, authorId: str, markingId: str):
        # Build a STIX2 Report object
        published_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        created_time = datetime.utcfromtimestamp(data["attributes"]["creation_date"]).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        modification_time = datetime.utcfromtimestamp(data["attributes"]["last_modification_date"]).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        report = Report(
            id=stix2.utils.generate_id("report", data["attributes"]["name"]),
            created_by_ref=authorId,
            created=created_time,
            modified=modification_time,
            name=data["attributes"]["name"],
            description=data["attributes"]["content"],
            published=published_time,
            report_types=data["attributes"].get("report_type", ["threat-report"]),
            object_refs=[indicatorId],
            object_marking_refs=[markingId]  # CHANGE: Now reports reference TLP marking
        )
        return report

    def _request_data_report(self, api_url: str, params=None):
        try:
            response = self.session.get(api_url, params=params, verify=self.config.ssl_verify)  # CHANGE: SSL configurable
            response.raise_for_status()
            return response.json()
        except requests.RequestException as err:
            self.helper.log_error(f"[API] Error fetching reports: {err}")
            return None

    def _request_data_report_association_indicator(self, api_url: str, report_id: str, params=None):
        try:
            response = self.session.get(f"{api_url}/{report_id}/associations", params=params, verify=self.config.ssl_verify)  # CHANGE: SSL configurable
            response.raise_for_status()
            output = response.json()
            nowDate = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")

            for association in output.get("data", []):
                if association["attributes"].get("top_icon_md5"):
                    md5 = association["attributes"]["top_icon_md5"][0]
                    patternSet = f"[ file:hashes.'MD5' = '{md5}' ]"

                    indicator = Indicator(
                        type="indicator",
                        name=association["attributes"]["name"],
                        description=association["attributes"]["description"],
                        pattern=patternSet,
                        pattern_type="stix",
                        valid_from=nowDate,
                        object_marking_refs=[stix2.TLP_WHITE.id]  # CHANGE: Indicators reference TLP marking
                    )
                    return indicator
            return None
        except requests.RequestException as err:
            self.helper.log_error(f"[API] Error fetching indicators: {err}")
            return None

    def _collect_intelligence(self) -> list:
        api_url = self.config.api_base_url
        stix_objects = []

        entities = self._request_data_report(api_url=api_url)
        if not entities:
            return []

        # Create author and marking
        author = Identity(
            id=stix2.utils.generate_id("identity", "Google Threat Intelligence"),
            name="Google Threat Intelligence",
            identity_class="organization"
        )
        marking = stix2.TLP_WHITE

        stix_objects.append(author)
        stix_objects.append(marking)

        for entity in entities.get("data", []):
            report_id = entity["id"]
            indicator = self._request_data_report_association_indicator(api_url=api_url, report_id=report_id)
            if not indicator:
                self.helper.log_info(f"No indicator for report {report_id}, skipping.")
                continue

            stix_objects.append(indicator)
            report = self.convert_GTI_Report(data=entity, indicatorId=indicator.id, authorId=author.id, markingId=marking.id)
            stix_objects.append(report)

        return stix_objects

    def run(self) -> None:
        self.helper.log_info("[CONNECTOR] Starting...")
        while True:
            try:
                self.process_message()
                time.sleep(self.config.sleep_interval)  # CHANGE: Configurable sleep interval
            except Exception as e:
                self.helper.log_error(f"[CONNECTOR] Error in main loop: {e}")

    def _initiate_work(self, timestamp: int) -> str:
        now = datetime.fromtimestamp(timestamp, timezone.utc)
        friendly_name = f"{self.helper.connect_name} run @ {now.strftime('%Y-%m-%d %H:%M:%S')}"
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)
        self.helper.log_info(f"[CONNECTOR] Work {work_id} initiated.")
        return work_id

    def process_message(self) -> None:
        now = datetime.now()
        current_time = int(now.timestamp())
        work_id = self._initiate_work(current_time)

        stix_objects = self._collect_intelligence()
        if not stix_objects:
            self.helper.log_info("[CONNECTOR] No STIX objects collected.")
            return

        bundle = stix2.Bundle(objects=stix_objects, allow_custom=True)

        try:
            self.helper.log_info("[CONNECTOR] Sending STIX bundle to OpenCTI...")
            self.helper.send_stix2_bundle(bundle, work_id=work_id)
            self.helper.log_info("[CONNECTOR] STIX bundle successfully sent.")
        except Exception as e:
            self.helper.log_error(f"[CONNECTOR] Failed to send STIX bundle: {e}")
            self.helper.log_error(bundle.serialize(pretty=True))  # CHANGE: Log full bundle on error

        current_state = {"last_run": current_time}
        self.helper.set_state(current_state)
        message = f"{self.helper.connect_name} connector successfully run at {now.strftime('%Y-%m-%d %H:%M:%S')}"
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

if __name__ == "__main__":
    try:
        connector = GTIConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
