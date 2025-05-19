#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <ctime>
#include <algorithm>  // For remove_if

using namespace std;

// Helper to convert time string to UNIX timestamp
time_t parseTime(const string& datetime) {
    struct tm tm = {};
    const char* result = strptime(datetime.c_str(), "%Y-%m-%d %H:%M:%S", &tm);
    if (result == nullptr || *result != '\0') {
        throw runtime_error("Invalid datetime format: " + datetime);
    }
    return mktime(&tm);
}

struct Event {
    time_t timestamp;
    string ip;
    string type;
};

// Parse one log line into Event
Event parseLogLine(const string& line) {
    string datetime, ip, eventType;
    
    try {
        // Extract timestamp
        size_t dtStart = line.find('[') + 1;
        if (dtStart == string::npos) throw runtime_error("Missing '['");
        
        size_t dtEnd = line.find(']', dtStart);
        if (dtEnd == string::npos) throw runtime_error("Missing ']'");
        
        datetime = line.substr(dtStart, dtEnd - dtStart);

        // Extract IP
        size_t ipPos = line.find("IP:", dtEnd);
        if (ipPos == string::npos) throw runtime_error("Missing 'IP:'");
        ipPos += 3; // Length of "IP:"
        
        size_t ipEnd = line.find(" ", ipPos);
        if (ipEnd == string::npos) ipEnd = line.length();
        
        ip = line.substr(ipPos, ipEnd - ipPos);

        // Extract Event Type
        size_t evPos = line.find("EVENT:", ipEnd);
        if (evPos == string::npos) throw runtime_error("Missing 'EVENT:'");
        evPos += 6; // Length of "EVENT:"
        
        eventType = line.substr(evPos);
        
        // Trim any whitespace
        eventType.erase(0, eventType.find_first_not_of(" \t\n\r\f\v"));
        eventType.erase(eventType.find_last_not_of(" \t\n\r\f\v") + 1);
        
        return { parseTime(datetime), ip, eventType };
    } catch (const exception& e) {
        throw runtime_error("Failed to parse log line: " + string(e.what()) + " in line: " + line);
    }
}

bool detectFailedLogins(const vector<Event>& events, const Event& current) {
    if (current.type != "FAILED_LOGIN") return false;

    int count = 0;
    for (const auto& e : events) {
        if (e.ip == current.ip && e.type == "FAILED_LOGIN" &&
            difftime(current.timestamp, e.timestamp) <= 60) {
            count++;
        }
    }
    return count >= 2; // Current makes it 3
}

bool detectOffHoursLogin(const Event& e) {
    if (e.type != "LOGIN") return false;
    struct tm* timeinfo = localtime(&e.timestamp);
    return timeinfo->tm_hour < 8 || timeinfo->tm_hour > 20;
}

int main() {
    string filename = "logs.txt";
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Error: Could not open file " << filename << endl;
        return 1;
    }
    
    string line;
    vector<Event> recentEvents;
    int lineNum = 0;

    while (getline(file, line)) {
        lineNum++;
        if (line.empty()) continue;
        
        Event e;
        try {
            e = parseLogLine(line);
            recentEvents.push_back(e);
        } catch (const exception& ex) {
            cerr << "Error on line " << lineNum << ": " << ex.what() << endl;
            continue;
        }

        if (detectFailedLogins(recentEvents, e)) {
            cout << "[ALERT] Brute force detected from IP: " << e.ip << endl;
        }

        if (detectOffHoursLogin(e)) {
            cout << "[ALERT] Off-hours login from IP: " << e.ip << endl;
        }

        time_t now = e.timestamp;
        recentEvents.erase(
            remove_if(recentEvents.begin(), recentEvents.end(),
                      [now](const Event& ev) { return difftime(now, ev.timestamp) > 300; }),
            recentEvents.end()
        );
    }

    return 0;
}
