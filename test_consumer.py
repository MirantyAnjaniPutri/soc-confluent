import os
import json
from confluent_kafka import Consumer, KafkaException, KafkaError
from dotenv import load_dotenv

load_dotenv()

TOPIC = os.getenv("SIEM_ALERTS_TOPIC")

print("=" * 60)
print("KAFKA CONSUMER TEST")
print("=" * 60)

print("Bootstrap:", os.getenv("CONFLUENT_BOOTSTRAP_SERVERS"))
print("Topic:", TOPIC)
print("API Key loaded:", bool(os.getenv("CONFLUENT_API_KEY")))
print("API Secret loaded:", bool(os.getenv("CONFLUENT_API_SECRET")))

config = {
    "bootstrap.servers": os.getenv(
        "CONFLUENT_BOOTSTRAP_SERVERS"
    ),

    "security.protocol": "SASL_SSL",
    "sasl.mechanisms": "PLAIN",

    "sasl.username": os.getenv(
        "CONFLUENT_API_KEY"
    ),

    "sasl.password": os.getenv(
        "CONFLUENT_API_SECRET"
    ),

    # IMPORTANT:
    # Use a NEW group while testing.
    "group.id": "siem-debug-consumer-001",

    "auto.offset.reset": "earliest",

    "enable.auto.commit": False,

    "client.id": "siem-debug-client",
}


def on_assign(consumer, partitions):

    print("\n" + "=" * 60)
    print("PARTITIONS ASSIGNED")
    print("=" * 60)

    for p in partitions:
        print(
            f"Topic={p.topic} "
            f"Partition={p.partition} "
            f"Offset={p.offset}"
        )

    consumer.assign(partitions)


consumer = Consumer(config)

try:

    print("\nSubscribing to:", TOPIC)

    consumer.subscribe(
        [TOPIC],
        on_assign=on_assign
    )

    print("Subscribed.")
    print("Waiting for messages...\n")

    while True:

        msg = consumer.poll(
            timeout=1.0
        )

        if msg is None:

            print(
                "No message yet..."
            )

            continue

        if msg.error():

            if (
                msg.error().code()
                == KafkaError._PARTITION_EOF
            ):

                print(
                    "Reached end of partition:",
                    msg.topic(),
                    msg.partition()
                )

                continue

            print(
                "KAFKA ERROR:",
                msg.error()
            )

            continue

        print("\n" + "=" * 60)
        print("🔥 MESSAGE RECEIVED")
        print("=" * 60)

        print(
            "Topic:",
            msg.topic()
        )

        print(
            "Partition:",
            msg.partition()
        )

        print(
            "Offset:",
            msg.offset()
        )

        print(
            "Key:",
            msg.key()
        )

        raw_value = msg.value()

        print(
            "Raw:",
            raw_value
        )

        try:

            value = json.loads(
                raw_value.decode("utf-8")
            )

            print(
                "\nJSON:"
            )

            print(
                json.dumps(
                    value,
                    indent=2
                )
            )

        except Exception as e:

            print(
                "JSON parsing failed:",
                e
            )

except KeyboardInterrupt:

    print("\nStopping...")

except Exception as e:

    print(
        "\nFATAL ERROR:",
        repr(e)
    )

finally:

    consumer.close()

    print(
        "Consumer closed."
    )