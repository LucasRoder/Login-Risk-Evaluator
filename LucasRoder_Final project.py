import json
from datetime import datetime

def evaluateLogin(event):

    # login event values extracted from dictionary
    userId = event["userId"]
    ipAddress = event["ipAddress"]
    geoCountry = event["geoCountry"]
    deviceFingerprint = event["deviceFingerprint"]
    loginTimeStr = event["loginTime"]
    failedAttemptsPastHour = int(event["failedAttemptsPastHour"])
    successfulLoginsPastDay = int(event["successfulLoginsPastDay"])

    # Convert string time to exact hour useing date time
    loginTime = datetime.fromisoformat(loginTimeStr)
    loginHour = loginTime.hour

    # risk calculator
    score = 0.0
    reasons = []

    # what behavior should look like
    expectedCountry = "US" # employee countries US / Canada
    knownDevices = {"winChrome120", "macSafari17", "linuxFirefox"} # employee devices
    typicalHours = range(7, 19)  # common employee working times 7 AM to  7PM


    # Country Check
    if geoCountry != expectedCountry:
        score += 0.4
        reasons.append("Unusual country login: " + geoCountry +".")
    else:
        reasons.append("Country is expected")

    # Time Check
    if loginHour not in typicalHours:
        score += 0.2
        reasons.append("Unusual login time: "  + str(loginHour) + ":00")
    else:
        reasons.append("Login during normal working hours")

    # Device Check
    if deviceFingerprint not in knownDevices:
        score += 0.3
        reasons.append(f"Unknown device used:" + deviceFingerprint)
    else:
        reasons.append("Recognized device")

    # Failed Attempts
    if failedAttemptsPastHour >= 10:
        score += 0.4
        reasons.append(str(failedAttemptsPastHour) + " failed login attempts procced with EXTREME caution")
    elif failedAttemptsPastHour >= 3:
        score += 0.25
        reasons.append(str(failedAttemptsPastHour) + " failed login attempts procced with caution")
    elif failedAttemptsPastHour > 0:
        score += 0.1
        reasons.append(str(failedAttemptsPastHour) + " failed login attempts")
    else:
        reasons.append("No failed login attempts")

    # Successful Login History
    if successfulLoginsPastDay == 0:
        score += 0.1
        reasons.append("No successful logins today")


    # score risk
    if score >= 0.75:
        riskLevel = "high"
        action = "block"
    elif score >= 0.4:
        riskLevel = "medium"
        action = "send MFA request"
    else:
        riskLevel = "low"
        action = "allow"

    # Return result
    return {
        "riskScore": round(score, 2),
        "riskLevel": riskLevel,
        "recommendedAction": action,
        "reasons": reasons
    }

#Json file
def loadEvents(filename):
    with open(filename, "r") as file: # opens file as read only
        return json.load(file) # returns file for analysis


#main
def main():
    print("Login Risk Detector")
    filename = input("Enter your JSON filename (include.json at end): ")
    if filename == "":
        filename = "logins.json"

    events = loadEvents(filename)

    # Loop through events and assign dictionary manually
    for i in range(len(events)):
        event = events[i]

        print("\n****************************")
        print(" Login Event #",i + 1)
        print("****************************")
        print("User:", event["userId"])
        print("IP:", event["ipAddress"])
        print("Country:", event["geoCountry"])
        print("Device:", event["deviceFingerprint"])
        print("Login Time:", event["loginTime"])


        result = evaluateLogin(event)

        print("\n--- RISK EVALUATION ---")
        print("Risk Score:", result["riskScore"])
        print("Risk Level:", result["riskLevel"])
        print("Action:", result["recommendedAction"])
        print("Reasons:")
        counter = 1
        for r in result["reasons"]:
            print(counter, r)
            counter +=1



if __name__ == "__main__":
    main()




