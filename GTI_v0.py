
import base64
import hashlib
import json
import urllib.parse
import yaml
import requests
from pycti import OpenCTIConnectorHelper, Identity, MarkingDefinition, StixCoreRelationship, Report
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
from stix2 import Indicator
import validators
import logging
import _socket

from config_variables import ConfigConnector

def _create_tlp_marking(level):
    mapping = {
        "white": stix2.TLP_WHITE,
        "clear": stix2.TLP_WHITE,
        "green": stix2.TLP_GREEN,
        "amber": stix2.TLP_AMBER,
        "amber+strict": stix2.MarkingDefinition(
            id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
            definition_type="statement",
            definition="statement": "custom",
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
        # Read config directly from environment
        self.config = ConfigConnector()
        self.session = requests.Session()

        headers = {
            "accept": "application/json",
            "x-apikey": self.config.api_key
        }

        self.session.headers.update(headers)

        self.helper = OpenCTIConnectorHelper(
            config=self.config.load, playbook_compatible=True
        )

    def convert_GTI_Report(self, data: dict, indicatorId: str):
        published_time = int(time.time())

        dt_object = datetime.fromtimestamp(published_time)
        published_time = dt_object.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        dt_object = datetime.fromtimestamp(data["attributes"]["creation_date"])
        created_time = dt_object.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        dt_object = datetime.fromtimestamp(data["attributes"]["last_modification_date"])
        modification_time = dt_object.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        id_generated_id = Report.generate_id(name="Google Threat Intelligence", identity_class="organization")
        created_by_ref = Identity.generate_id(name=data["attributes"]["name"], published="true")

        reportReturn = stix2.Report(
            type="report",
            spec_version="2.1",
            id=id_generated_id,
            created_by_ref=created_by_ref,
            created=created_time,
            modified=modification_time,
            name=data["attributes"]["name"],
            description=data["attributes"]["content"],
            published=str(published_time),
            report_types=data["attributes"]["report_type"],
            object_refs=indicatorId
        )

        testReturn = {
            "type": "report",
            "spec_version": "2.1",
            "id": id_generated_id,
            "created_by_ref": created_by_ref,
            "created": created_time,
            "modified": modification_time,
            "name": data["attributes"]["name"],
            "description": data["attributes"]["content"],
            "published": str(published_time),
            "report_types": data["attributes"]["report_type"]
        }

        return testReturn

    def _request_data_report(self, api_url: str, params=None):
        try:
            response = self.session.get(api_url, headers=self.session.headers, params=params, verify=False)

            self.helper.connector_logger.info(
                "[API] Get Request to endpoint: ", {"url_path": api_url}
            )

            response.raise_for_status()
            return response.json()

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": api_url, "error": str(err)}
            )
            return None

    def _request_data_report_association_indicator(self, api_url: str, report_id: str, params=None):
        try:
            response = self.session.get(api_url + '/' + report_id + "/associations", headers=self.session.headers, params=params, verify=False)
            output = response.json()

            nowDate = int(time.time())
            nowDate = datetime.fromtimestamp(nowDate)
            nowDate = nowDate.strftime("%Y-%m-%dT%H:%M:%S.000Z")

            for association in output["data"]:
                if len(str(association["attributes"]["top_icon_md5"])) < 1:
                    pass
                else:
                    input = str(association["attributes"]["top_icon_md5"][0])
                    patternSet = "[ file:hashes.'MD5' = '" + input + "' ]"

                    indicator1 = stix2.Indicator(
                        type="indicator",
                        name=association["attributes"]["name"],
                        description=association["attributes"]["description"],
                        pattern=patternSet,
                        pattern_type="stix",
                        valid_from=nowDate
                    )

                    break
            return indicator1
        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": api_url, "error": str(err)}
            )
            return None

    def _collect_intelligence(self) -> list:
        api_url = self.config.api_base_url
        api_token = self.config.api_key

        headers = {
            "accept": "application/json",
            "x-apikey": api_token,
        }

        stix_objects = []

        entities = self._request_data_report(api_url=api_url)

        for entity in entities["data"]:
            report_id = entity["id"]

            indicator = self._request_data_report_association_indicator(api_url=api_url, report_id=report_id)
            report = self.convert_GTI_Report(data=entity, indicatorId=indicator.id)

            stix_objects.append(report)
            stix_objects.append(indicator)

        if len(stix_objects):
            author = stix2.Identity(
                id=Identity.generate_id(name="Google Threat Intelligence", identity_class="organization"),
                name="Google Threat Intelligence",
                description="Google Threat Intelligence intel, virustotal and mandiant merged APIs",
                identity_class="organization",
            )
            mapping = stix2.TLP_WHITE
            stix_objects.append(author)
            stix_objects.append(mapping)

        return stix_objects

    def run(self) -> None:
        self.helper.log_info("[CONNECTOR] Fetching datasets...")

        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        while True:
            self.helper.process_data()
            self.helper.force_ping()

            if get_run_and_terminate and self.helper.get_run_and_terminate():
                break

            self.process_message()

    def _initiate_work(self, timestamp: int) -> str:
        now = datetime.fromtimestamp(timestamp, timezone.utc)
        friendly_name = f"{self.helper.connect_name} run @ " + now.strftime("%Y-%m-%d %H:%M:%S")

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        info_msg = f"[CONNECTOR] New work {work_id} initiated..."
        self.helper.log_info(info_msg)

        return work_id

    def process_message(self) -> None:
        try:
            now = datetime.now()
            current_time = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                msg = "[CONNECTOR] Connector last run: " + datetime.fromtimestamp(last_run, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                self.helper.log_info(msg)
            else:
                last_run = None
                msg = "[CONNECTOR] Connector has never run..."
                self.helper.log_info(msg)

            if last_run is None:
                work_id = self._initiate_work(current_time)
                self.helper.api.work.initiate_work(work_id)
                self.helper.update_connector_state(current_time, work_id)

            stix_objects = self._collect_intelligence()

            if len(stix_objects):
                bundle = self.helper.stix2_create_bundle(stix_objects)
                try:
                    self.helper.send_stix2_bundle(bundle, work_id=work_id)
                except Exception as ex:
                    self.helper.log_error(f"An error occurred while sending STIX bundle: {ex}")
                    self.helper.log_info("GTI STIX bundle sent.")

            else:
                self.helper.log_info("[Censys] No data returned for STIX bundle")

            self.helper.connector_logger.debug(
                "Getting current state and update it with the last run of the connector",
                {"current_timestamp": current_time},
            )

            current_state = self.helper.get_state()
            if current_state is not None:
                current_state["last_run"] = current_time
            else:
                current_state = {"last_run": current_time}

            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(datetime.fromtimestamp(current_time, timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
            )
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            msg = "[CONNECTOR] Connector stop..."
            self.helper.log_info(msg)
            sys.exit(0)
        except Exception as e:
            error_msg = f"[CONNECTOR] Error while processing data: {str(e)}"
            self.helper.log_error(error_msg)


if __name__ == "__main__":
    try:
        connecter = GTIConnector()
        connecter.run()
    except Exception:
        traceback.print_exc()
        exit(1)
