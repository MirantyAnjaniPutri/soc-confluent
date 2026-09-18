import os
from dotenv import load_dotenv
from confluent_kafka import Consumer

load_dotenv()

bootstrap = os.getenv("CONFLUENT_BOOTSTRAP_SERVERS")
api_key = os.getenv("CONFLUENT_API_KEY")
api_secret = os.getenv("CONFLUENT_API_SECRET")

print("Bootstrap:", bootstrap)
print("API Key loaded:", bool(api_key))
print("API Secret loaded:", bool(api_secret))

config = {
    "bootstrap.servers": bootstrap,
    "security.protocol": "SASL_SSL",
    "sasl.mechanisms": "PLAIN",
    "sasl.username": api_key,
    "sasl.password": api_secret,
    "group.id": "connection-test",
    "auto.offset.reset": "earliest",
}

consumer = Consumer(config)

try:

    metadata = consumer.list_topics(
        timeout=10
    )

    print("\n✅ CONNECTION SUCCESSFUL")
    print("Cluster ID:", metadata.cluster_id)

    print("\nTopics:")

    for topic in metadata.topics:
        print(" -", topic)

except Exception as e:

    print("\n❌ CONNECTION FAILED")
    print(e)

finally:

    consumer.close()