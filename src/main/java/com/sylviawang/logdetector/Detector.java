package com.sylviawang.logdetector;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * The three detection rules, same logic as the Python version (app/detector.py).
 * Each rule uses a 5-minute window and a threshold of 3.
 */
public class Detector {

    static final Duration WINDOW = Duration.ofMinutes(5);
    static final int THRESHOLD = 3;

    /** Rule 1: an IP with 3 or more failed logins within 5 minutes. One alert per IP. */
    public static List<Alert> detectBruteForce(List<LoginEvent> logs) {
        List<Alert> alerts = new ArrayList<>();

        List<LoginEvent> failed = new ArrayList<>();
        for (LoginEvent event : logs) {
            if (event.isFailed()) {
                failed.add(event);
            }
        }

        for (Map.Entry<String, List<LoginEvent>> entry : groupBy(failed, LoginEvent::ipAddress).entrySet()) {
            List<LoginEvent> group = sortByTime(entry.getValue());

            for (LoginEvent first : group) {
                LocalDateTime end = first.timestamp().plus(WINDOW);
                int count = 0;
                for (LoginEvent event : group) {
                    if (inRange(event.timestamp(), first.timestamp(), end)) {
                        count++;
                    }
                }
                if (count >= THRESHOLD) {
                    alerts.add(new Alert(Alert.BRUTE_FORCE, entry.getKey(), null, 0,
                            "Multiple failed login attempts within 5 minutes"));
                    break;
                }
            }
        }
        return alerts;
    }

    /** Rule 2: a successful login after 3 or more failed logins by the same user in the previous 5 minutes. */
    public static List<Alert> detectSuspiciousSuccess(List<LoginEvent> logs) {
        List<Alert> alerts = new ArrayList<>();

        for (Map.Entry<String, List<LoginEvent>> entry : groupBy(logs, LoginEvent::user).entrySet()) {
            List<LoginEvent> group = sortByTime(entry.getValue());

            for (int i = 0; i < group.size(); i++) {
                LoginEvent current = group.get(i);
                if (!current.isSuccess()) {
                    continue;
                }

                LocalDateTime windowStart = current.timestamp().minus(WINDOW);
                int recentFailures = 0;
                for (int j = 0; j < i; j++) {
                    LoginEvent previous = group.get(j);
                    if (previous.isFailed() && !previous.timestamp().isBefore(windowStart)) {
                        recentFailures++;
                    }
                }

                if (recentFailures >= THRESHOLD) {
                    alerts.add(new Alert(Alert.SUSPICIOUS_SUCCESS, current.ipAddress(), entry.getKey(), 0,
                            "Successful login after multiple failed attempts"));
                }
            }
        }
        return alerts;
    }

    /** Rule 3: an IP used by 3 or more different users within 5 minutes. One alert per IP. */
    public static List<Alert> detectMultipleUsers(List<LoginEvent> logs) {
        List<Alert> alerts = new ArrayList<>();

        for (Map.Entry<String, List<LoginEvent>> entry : groupBy(logs, LoginEvent::ipAddress).entrySet()) {
            List<LoginEvent> group = sortByTime(entry.getValue());

            for (LoginEvent first : group) {
                LocalDateTime end = first.timestamp().plus(WINDOW);
                Set<String> users = new HashSet<>();
                for (LoginEvent event : group) {
                    if (inRange(event.timestamp(), first.timestamp(), end)) {
                        users.add(event.user());
                    }
                }
                if (users.size() >= THRESHOLD) {
                    alerts.add(new Alert(Alert.MULTIPLE_USERS, entry.getKey(), null, users.size(),
                            "Multiple user accounts accessed from the same IP"));
                    break;
                }
            }
        }
        return alerts;
    }

    /** Runs all three rules in the same order as the Python /alerts endpoint. */
    public static List<Alert> detectAll(List<LoginEvent> logs) {
        List<Alert> all = new ArrayList<>();
        all.addAll(detectBruteForce(logs));
        all.addAll(detectSuspiciousSuccess(logs));
        all.addAll(detectMultipleUsers(logs));
        return all;
    }

    // start <= time <= end (both ends included, like the pandas filter)
    private static boolean inRange(LocalDateTime time, LocalDateTime start, LocalDateTime end) {
        return !time.isBefore(start) && !time.isAfter(end);
    }

    private static Map<String, List<LoginEvent>> groupBy(List<LoginEvent> logs, Function<LoginEvent, String> key) {
        Map<String, List<LoginEvent>> groups = new LinkedHashMap<>();
        for (LoginEvent event : logs) {
            groups.computeIfAbsent(key.apply(event), k -> new ArrayList<>()).add(event);
        }
        return groups;
    }

    private static List<LoginEvent> sortByTime(List<LoginEvent> events) {
        List<LoginEvent> sorted = new ArrayList<>(events);
        sorted.sort(Comparator.comparing(LoginEvent::timestamp));
        return sorted;
    }
}
