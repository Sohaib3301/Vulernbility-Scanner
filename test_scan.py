
from IoTvuln import scan_ports

results = scan_ports(
    "127.0.0.1",
    ports=[22, 80, 443, 8080]
)

for result in results:
    print(
        f"Port {result['port']}: {result['status']}"
    )
