import random

ips = [f"192.168.1.{i}" for i in range(10, 101)]

with open("sample.log", "w") as f:

    # Critical attackers
    critical_ips = [
        "192.168.1.50",
        "192.168.1.110",
        "192.168.1.130",
        "192.168.1.90",
        "192.168.1.75"
    ]

    for ip in critical_ips:
        for _ in range(random.randint(20, 40)):
            f.write(
                f"Jun 2 10:{random.randint(10,59)}:{random.randint(10,59)} kali sshd[{random.randint(1000,9999)}]: Failed password for root from {ip} port 22 ssh2\n"
            )

    # Failed login attempts
    for _ in range(600):
        ip = random.choice(ips)
        f.write(
            f"Jun 2 11:{random.randint(10,59)}:{random.randint(10,59)} kali sshd[{random.randint(1000,9999)}]: Failed password for root from {ip} port 22 ssh2\n"
        )

    # Invalid users
    for _ in range(300):
        ip = random.choice(ips)
        f.write(
            f"Jun 2 12:{random.randint(10,59)}:{random.randint(10,59)} kali sshd[{random.randint(1000,9999)}]: Invalid user admin from {ip}\n"
        )

    # Authentication failures
    for _ in range(300):
        ip = random.choice(ips)
        f.write(
            f"Jun 2 13:{random.randint(10,59)}:{random.randint(10,59)} kali sshd[{random.randint(1000,9999)}]: authentication failure from {ip}\n"
        )

    # Successful logins
    for _ in range(800):
        ip = random.choice(ips)
        f.write(
            f"Jun 2 14:{random.randint(10,59)}:{random.randint(10,59)} kali sshd[{random.randint(1000,9999)}]: Accepted password for user from {ip} port 22 ssh2\n"
        )

print("Generated sample.log successfully")
