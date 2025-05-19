from datetime import datetime, timedelta
import random
import math

# Base template for log entries
template = "[{}] IP:{} PORT:{} EVENT:{}"

# Define some common ports and their associated event types
common_events = [
    ("22", "LOGIN"),
    ("22", "FAILED_LOGIN"),
    ("80", "PORT_SCAN"),
    ("443", "PORT_SCAN"),
    ("21", "PORT_SCAN"),
    ("3306", "PORT_SCAN"),
    ("8080", "PORT_SCAN"),
    ("23", "PORT_SCAN"),
    ("25", "PORT_SCAN"),
    ("110", "PORT_SCAN"),
    ("143", "PORT_SCAN"),
    ("993", "PORT_SCAN"),
]

# Generate some random IPs
def random_ip():
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

def generate_daily_logs():
    base_date = datetime(2025, 5, 19)  # Today's date
    total_entries = 18000
    logs = []
    
    # Define peak hours (9 AM to 5 PM)
    peak_hours = list(range(9, 17))
    
    # Generate timestamps with more events during business hours
    for i in range(total_entries):
        # Normal distribution around business hours
        hour = int(random.normalvariate(13, 4))  # Mean at 1 PM, std dev of 4 hours
        hour = max(0, min(23, hour))  # Clamp to 0-23
        
        # Adjust distribution to have more events during business hours
        if hour in peak_hours and random.random() < 0.7:  # 70% chance to be in peak hours
            hour = random.choice(peak_hours)
        
        # More granular time distribution
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        
        # Create timestamp
        timestamp = base_date + timedelta(
            hours=hour,
            minutes=minute,
            seconds=second,
            milliseconds=random.randint(0, 999)
        )
        
        # Weighted event types (more failed logins and port scans)
        weights = [
            0.2,  # LOGIN
            0.4,  # FAILED_LOGIN
            0.4   # PORT_SCAN
        ]
        event_type = random.choices(
            ["LOGIN", "FAILED_LOGIN", "PORT_SCAN"],
            weights=weights
        )[0]
        
        # Select appropriate port based on event type
        if event_type == "LOGIN":
            port = "22"  # SSH
        elif event_type == "FAILED_LOGIN":
            port = "22"  # SSH
        else:  # PORT_SCAN
            port = random.choice(["80", "443", "21", "3306", "8080", "23", "25", "110", "143", "993"])[0]
        
        # Generate log entry
        log_entry = template.format(
            timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            random_ip(),
            port,
            event_type
        )
        logs.append((timestamp, log_entry))
    
    # Sort logs by timestamp
    logs.sort()
    return [log[1] for log in logs]

# Write logs to file
with open('logs.txt', 'w') as f:
    for log in generate_daily_logs():
        f.write(log + '\n')

print("Generated logs.txt with a full day of log entries")
