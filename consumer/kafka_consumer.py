import os
import json
from confluent_kafka import Consumer

def create_siem_consumer(group_suffix):
    return Consumer({
        "bootstrap.servers": os.getenv("CONFLUENT_BOOTSTRAP_SERVERS"),
        "security.protocol": "SASL_SSL",
        "sasl.mechanisms": "PLAIN",
        "sasl.username": os.getenv("CONFLUENT_API_KEY"),
        "sasl.password": os.getenv("CONFLUENT_API_SECRET"),
        "group.id": f"siem-dashboard-{group_suffix}",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    })

def decode_confluent_message(raw_bytes):
    """
    Strips Confluent Schema Registry magic byte (0x00) + 4-byte Schema ID 
    if present before parsing JSON data.
    """
    if len(raw_bytes) > 5 and raw_bytes[0] == 0:
        raw_bytes = raw_bytes[5:]
    return json.loads(raw_bytes.decode("utf-8"))