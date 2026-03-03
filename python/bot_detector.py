import time
import os

LOG_FILE = os.path.join(os.path.dirname(__file__), "../logs/suspicious_activity.log")
class BotDetector:
    def __init__(self):
        self.entries = {} #Stores timestamps of user submissions
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    def log_entry(self, user_id):
        now = time.time()
        if user_id in self.entries:
            self.entries[user_id].append(now)
        else:
            self.entries[user_id] = [now]
    
    def is_suspicious(self, user_id, threshold=3, interval=10):
        """
        Returns True if user submits more than 'threshold' entries
         in 'interval' seconds.
        """
        if user_id not in self.entries:
            return False
        
        times = self.entries[user_id] #Keeps only enties in the last 'interval' seconds
        times = [t for t in times if time.time() - t < interval]
        self.entries[user_id] = times #Update entries to keep only recent ones
        
        if len(times) > threshold:
            self.log_to_file(user_id, len(times))
            return True
        return False
    
    def log_to_file(self, user_id, count):
        """ Appends suspicious activity to a log file"""
        with open(LOG_FILE, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime() )
            f.write(f"{timestamp} - Suspicious activity detected for {user_id}, count: {count}\n")

# CLI demo
if __name__ == "__main__":
    detector = BotDetector()
    print("Bot detection system initialized.")
    print("Enter 'exit' to quit.\n")

    while True:
        uid = input("Enter user ID: ").strip()
        if not uid:
            print("PLease enter a valid user ID.\n")
            continue
        if uid.lower() == "exit":
            break


        detector.log_entry(uid)
        if detector.is_suspicious(uid):
            print(f"[ALERT] Suspicious activity detected for user {uid}\n")
        else:
            print(f"{uid} logged successfully.\n")
