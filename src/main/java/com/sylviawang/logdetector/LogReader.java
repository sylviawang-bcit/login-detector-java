package com.sylviawang.logdetector;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/** Reads a login log CSV with the header: timestamp,user,ip_address,status */
public class LogReader {

    private static final String HEADER = "timestamp,user,ip_address,status";
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static List<LoginEvent> read(Path file) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(file)) {
            return parse(reader.lines().toList());
        }
    }

    /** Parses CSV lines. The first line must be the header. Blank lines are skipped. */
    public static List<LoginEvent> parse(List<String> lines) {
        List<LoginEvent> events = new ArrayList<>();
        if (lines.isEmpty()) {
            return events;
        }
        if (!lines.get(0).trim().equals(HEADER)) {
            throw new IllegalArgumentException("Unexpected header: " + lines.get(0));
        }

        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                continue;
            }
            int lineNumber = i + 1;
            String[] parts = line.split(",");
            if (parts.length != 4) {
                throw new IllegalArgumentException("Line " + lineNumber + ": expected 4 fields but got " + parts.length);
            }

            LocalDateTime timestamp;
            try {
                timestamp = LocalDateTime.parse(parts[0].trim(), TIME_FORMAT);
            } catch (DateTimeParseException e) {
                throw new IllegalArgumentException("Line " + lineNumber + ": bad timestamp '" + parts[0] + "'");
            }

            String status = parts[3].trim();
            if (!status.equals("success") && !status.equals("failed")) {
                throw new IllegalArgumentException("Line " + lineNumber + ": unknown status '" + status + "'");
            }

            events.add(new LoginEvent(timestamp, parts[1].trim(), parts[2].trim(), status));
        }
        return events;
    }
}
