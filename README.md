# Login Detector (Java)

A Java version of the detection rules from my Python project
[Security Log Analysis & Threat Detection Tool](https://github.com/sylviawang-bcit/security-log-threat-detection).
I rewrote the three rules in Java to practise Java and JUnit 5, using the same sample log data,
and checked that both versions find the same 6 alerts.

## Detection rules

All rules use a 5-minute window and a threshold of 3.

| Rule | Groups by | Raises an alert when |
| --- | --- | --- |
| Brute Force | IP address | 3 or more failed logins within 5 minutes (one alert per IP) |
| Suspicious Login After Multiple Failures | User | A successful login has 3 or more failed logins by the same user in the 5 minutes before it |
| Suspicious Multiple-User Login Activity | IP address | 3 or more different users log in from the IP within 5 minutes (one alert per IP) |

## Tech stack

- Java 17
- JUnit 5 (`@Test`, `@Nested`, `@ParameterizedTest`, `@TempDir`, `@BeforeAll`)
- Maven
- GitHub Actions (runs `mvn test` on every push and pull request to `main`)

## Project structure

```text
login-detector-java/
├── .github/workflows/ci.yml        # runs the tests on GitHub
├── data/login_logs.csv             # same sample data as the Python version
├── pom.xml
└── src/
    ├── main/java/com/sylviawang/logdetector/
    │   ├── LoginEvent.java         # one row of the log
    │   ├── Alert.java              # one alert
    │   ├── LogReader.java          # reads and checks the CSV
    │   ├── Detector.java           # the three rules
    │   └── Main.java               # prints all alerts
    └── test/java/com/sylviawang/logdetector/
        ├── DetectorTest.java       # unit tests for each rule
        ├── LogReaderTest.java      # CSV parsing, including bad input
        └── SampleDataTest.java     # runs all rules on data/login_logs.csv
```

## Run it

```bash
mvn test          # run all JUnit tests
mvn compile exec:java          # print alerts for data/login_logs.csv
```

## What the tests cover

- **Each rule, positive case**: the same cases as the pytest tests in the Python project.
- **Cases that should not alert**: only 2 failures, failures spread over more than 5 minutes,
  failures by different users, failures after the success, one user logging in many times.
- **Edge cases**: a failure exactly 5 minutes later is counted, unsorted input, many failures
  still give only one alert per IP, empty log.
- **Bad input**: wrong header, missing field, unknown status, wrong date format, impossible hour.
  Bad lines throw an error with the line number instead of being skipped.
- **Sample data**: all rules on `data/login_logs.csv` give 6 alerts, the same as the Python version.

## Differences from the Python version

- No pandas: grouping and the 5-minute window are written with plain loops and `LocalDateTime`.
- The CSV reader checks each line and reports which line is wrong. The Python version relies on pandas.
- No REST API yet. The Python version serves alerts through Flask at `/alerts`.
