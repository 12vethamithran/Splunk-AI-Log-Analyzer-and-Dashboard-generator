"""
Main entry point for Splunk AI Log Analyzer
Modified to generate dashboard XML file instead of creating in Splunk
"""

import os
from dotenv import load_dotenv
from splunk_connection_py import SimpleSplunkConnector
from log_processor_py import LogProcessor


def generate_dashboard_xml(log_type, index_name, output_path):
    """Generate tailored XML dashboard for each log type"""

    if log_type == "firewall" or log_type == "firewall_custom":
        panels = f"""
  <row>
    <panel>
      <chart>
        <title>Top Source IPs</title>
        <search>
          <query>index={index_name} sourcetype={log_type} | top src_ip</query>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Top Destination IPs</title>
        <search>
          <query>index={index_name} sourcetype={log_type} | top dst_ip</query>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Actions (Allow vs Block)</title>
        <search>
          <query>index={index_name} sourcetype={log_type} | top action</query>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Top Protocols</title>
        <search>
          <query>index={index_name} sourcetype={log_type} | top protocol</query>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Top Destination Ports</title>
        <search>
          <query>index={index_name} sourcetype={log_type} | top dst_port</query>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Blocked Traffic Over Time</title>
        <search>
          <query>index={index_name} sourcetype={log_type} action=BLOCK | timechart count</query>
        </search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
  </row>
"""
    elif log_type == "apache":
        panels = f"""
  <row>
    <panel>
      <chart>
        <title>Top Requested URLs</title>
        <search>
          <query>index={index_name} sourcetype=apache | top url</query>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Status Code Distribution</title>
        <search>
          <query>index={index_name} sourcetype=apache | top status_code</query>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
"""
    elif log_type == "dns":
        panels = f"""
  <row>
    <panel>
      <chart>
        <title>Top Queried Domains</title>
        <search>
          <query>index={index_name} sourcetype=dns | top domain</query>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Query Types</title>
        <search>
          <query>index={index_name} sourcetype=dns | top query_type</query>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
"""
    elif log_type == "syslog":
        panels = f"""
  <row>
    <panel>
      <chart>
        <title>Top Processes</title>
        <search>
          <query>index={index_name} sourcetype=syslog | top process</query>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Frequent Messages</title>
        <search>
          <query>index={index_name} sourcetype=syslog | top message</query>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
  </row>
"""
    else:  # fallback
        panels = ""

    xml_content = f"""
<dashboard version="1.1">
  <label>AI Generated {log_type.title()} Dashboard</label>

  <row>
    <panel>
      <chart>
        <title>Events over Time</title>
        <search>
          <query>index={index_name} sourcetype={log_type} | timechart count</query>
        </search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <table>
        <title>Raw Events (Latest 20)</title>
        <search>
          <query>index={index_name} sourcetype={log_type} | head 20</query>
        </search>
      </table>
    </panel>
  </row>

  {panels}
</dashboard>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(xml_content.strip())
    print(f"📄 Dashboard XML written to {output_path}")


def main():
    # Load env vars
    load_dotenv()
    index_name = os.getenv("DEFAULT_INDEX", "main")
    log_file = os.getenv("LOG_FILE")
    output_xml = os.getenv("OUTPUT_XML", "generated_dashboard.xml")

    print("🚀 Starting Splunk AI Log Analyzer...")
    print(f"📍 Index: {index_name}")
    print(f"📄 Log file: {log_file}")

    # Initialize Splunk connection
    connector = SimpleSplunkConnector()
    if not connector.connect():
        print("❌ Failed to connect to Splunk. Check your credentials and configuration.")
        return

    # Load logs
    if not os.path.exists(log_file):
        print(f"❌ Log file not found: {log_file}")
        return

    print(f"📖 Reading log file: {log_file}")
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            log_lines = f.readlines()
        print(f"📊 Loaded {len(log_lines)} lines from log file")
    except Exception as e:
        print(f"❌ Error reading log file: {e}")
        return

    # Detect type + extract
    processor = LogProcessor()
    log_type = processor.detect_log_type(log_lines)
    
    if log_type == 'unknown':
        print("❌ Could not detect log type. Please check your log format.")
        return
    
    extracted_data = processor.extract_fields(log_lines, log_type)

    # Send events to Splunk
    if extracted_data:
        print(f"📤 Sending {len(extracted_data)} events to Splunk...")
        success = connector.send_events(index_name, extracted_data, log_type)
        if success:
            # Write tailored dashboard XML
            generate_dashboard_xml(log_type, index_name, output_xml)
            print(f"🎉 Process completed successfully!")
            print(f"📊 Dashboard XML saved as: {output_xml}")
            print(f"🔍 You can now search your data in Splunk using: index={index_name} sourcetype={log_type}")
        else:
            print("❌ Failed to send events to Splunk")
    else:
        print("⚠️ No extracted data, skipping Splunk upload & XML generation")


if __name__ == "__main__":
    main()
