import os
import json
import time
import random
from datetime import datetime
from confluent_kafka import Producer
from dotenv import load_dotenv

load_dotenv()

conf = {
    'bootstrap.servers': os.getenv("CONFLUENT_BOOTSTRAP_SERVERS"),
    'security.protocol': 'SASL_SSL',
    'sasl.mechanisms': 'PLAIN',
    'sasl.username': os.getenv("CONFLUENT_API_KEY"),
    'sasl.password': os.getenv("CONFLUENT_API_SECRET")
}

producer = Producer(conf)

def delivery_report(err, msg):
    if err is not None:
        print(f"Message delivery failed: {err}")

def generate_alert():
    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    types = ["Brute Force Attempt", "Unauthorized Access", "Malware Detected", "Data Exfiltration"]
    return {
        "event_time": datetime.utcnow().isoformat(),
        "alert_severity": random.choice(severities),
        "alert_type": random.choice(types),
        "source_ip": f"192.168.1.{random.randint(1, 254)}",
        "destination_ip": f"10.0.0.{random.randint(1, 254)}",
        "hostname": f"host-{random.randint(100, 999)}",
        "access_group": "SecOps",
        "description": "Automated security alert event triggered."
    }

if __name__ == "__main__":
    topic = os.getenv("SIEM_ALERTS_TOPIC")
    print("Sending events to Confluent Kafka...")
    try:
        while True:
            event = generate_alert()
            producer.produce(
                topic, 
                key=event["source_ip"], 
                value=json.dumps(event), 
                callback=delivery_report
            )
            producer.poll(0)
            time.sleep(2)
    except KeyboardInterrupt:
        producer.flush()