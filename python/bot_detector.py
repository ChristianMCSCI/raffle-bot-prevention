import time
import os

# Define the path for the suspicious activity log file.
# This creates a logs directory one level up from this file.
LOG_FILE = os.path.join(os.path.dirname(__file__), "../logs/suspicious_activity.log")
class BotDetector:
    def __init__(self):
        # Dictionary to store user activity.
        # Format:
        # {
        #   "user_id": [timestamp1, timestamp2, ...]
        # }
        self.entries = {} #Stores timestamps of user submissions
        # Ensure the logs directory exists.
        # If it does not exist, create it.
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    def log_entry(self, user_id):
        
        now = time.time()
        
        if user_id in self.entries:
            # Append new timestamp if user already exists
            self.entries[user_id].append(now)
        else:
            # Create new list if first submission
            self.entries[user_id] = [now]
    
    def is_suspicious(self, user_id, threshold=3, interval=10):
        """
        Returns True if user submits more than 'threshold' entries
         in 'interval' seconds.
        """
        # If user has no recorded activity, they cannot be suspicious.
        if user_id not in self.entries:
            return False
        
        times = self.entries[user_id] #Keeps only enties in the last 'interval' seconds
        
        # Filter timestamps to keep only those within the interval window
        # (i.e., recent submissions)
        times = [t for t in times if time.time() - t < interval]

        # Update stored entries to remove old timestamps
        self.entries[user_id] = times #Update entries to keep only recent ones

        # Check if number of recent submissions exceeds threshold
        if len(times) > threshold:
            self.log_to_file(user_id, len(times))
            return True
        return False
    
    def log_to_file(self, user_id, count):
        """ Appends suspicious activity to a log file"""
        with open(LOG_FILE, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime() )

            # Write structured log entry
            f.write(f"{timestamp} - Suspicious activity detected for {user_id}, count: {count}\n")

# CLI demo
if __name__ == "__main__":
    detector = BotDetector()
    print("Bot detection system initialized.")
    print("Enter 'exit' to quit.\n")

    while True:
        uid = input("Enter user ID: ").strip()
        # Validate input
        if not uid:
            print("PLease enter a valid user ID.\n")
            continue

        # Exit condition
        if uid.lower() == "exit":
            break

        # Log user submission
        detector.log_entry(uid)

        # Check if user activity is suspicious
        if detector.is_suspicious(uid):
            print(f"[ALERT] Suspicious activity detected for user {uid}\n")
        else:
            print(f"{uid} logged successfully.\n")

