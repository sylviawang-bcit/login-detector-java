package com.sylviawang.logdetector;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/** Reads a log file (default: data/login_logs.csv) and prints every alert. */
public class Main {

    public static void main(String[] args) throws IOException {
        Path file = Path.of(args.length > 0 ? args[0] : "data/login_logs.csv");
        List<LoginEvent> logs = LogReader.read(file);
        List<Alert> alerts = Detector.detectAll(logs);

        System.out.println("Read " + logs.size() + " log entries, found " + alerts.size() + " alerts:");
        for (Alert alert : alerts) {
            System.out.println(alert);
        }
    }
}
