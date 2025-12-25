THRESHOLD = 5

def read_logs():
    with open("logs/auth.log", "r") as file:
        return file.readlines()

def detect_failed_logins(logs):
    failed_logins = {}

    for line in logs:
        if "Failed password" in line:
            parts = line.split()
            ip = parts[-1]

            if ip in failed_logins:
                failed_logins[ip] += 1
            else:
                failed_logins[ip] = 1

    return failed_logins

def generates_alerts(failed_logins):
    alerts =[]

    for ip, count in failed_logins.items():
        if count >= THRESHOLD:
            alerts.append(
                f"ALERT: Brute-force attack detected from {ip}"
                f"({count} failed login attempts)"
            )
    return alerts

def create_incident_report(alerts):
    with open("incident_report.txt", "w") as report:
        report.write("SIEM INCIDENT REPORT\n")
        report.write("====================\n")

        for alert in alerts:
            report.write(alert + "\n")

    print("Incident Report Generated Successfully")

def main():
    logs = read_logs()
    failed_logins = detect_failed_logins(logs)
    alerts = generates_alerts(failed_logins)

    if alerts:
        for alert in alerts:
            print(alert)
        create_incident_report(alerts)
    else:
        print("No security incidents detected.")

if __name__=="__main__":
    main()