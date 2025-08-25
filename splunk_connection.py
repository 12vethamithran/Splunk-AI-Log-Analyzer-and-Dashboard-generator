"""
Splunk Connection Utility
Handles authentication and event sending only
"""

import os
import json
import splunklib.client as client
import splunklib.results as results
from dotenv import load_dotenv

class SimpleSplunkConnector:
    def __init__(self):
        load_dotenv()
        self.host = os.getenv("SPLUNK_HOST", "localhost")
        self.port = int(os.getenv("SPLUNK_PORT", "8089"))
        self.username = os.getenv("SPLUNK_USERNAME")
        self.password = os.getenv("SPLUNK_PASSWORD")
        self.scheme = os.getenv("SPLUNK_SCHEME", "https")
        self.verify_ssl = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"
        self.service = None

    def connect(self):
        """Connect to Splunk instance"""
        print(f"🔌 Connecting to Splunk at {self.host}:{self.port}")
        try:
            self.service = client.connect(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                scheme=self.scheme
            )
            print("✅ Connected to Splunk successfully")
            return True
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False

    def send_events(self, index_name, events, log_type="custom_logs"):
        """Send events to Splunk with dynamic sourcetype"""
        try:
            if index_name not in [idx.name for idx in self.service.indexes]:
                print(f"⚠️ Index '{index_name}' does not exist in Splunk")
                return False

            index = self.service.indexes[index_name]
            for event in events:
                index.submit(json.dumps(event), sourcetype=log_type)
            print(f"✅ Sent {len(events)} events to '{index_name}' with sourcetype={log_type}")
            return True
        except Exception as e:
            print(f"❌ Error sending events: {e}")
            return False
