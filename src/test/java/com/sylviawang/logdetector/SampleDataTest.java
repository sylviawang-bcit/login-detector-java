package com.sylviawang.logdetector;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Runs all rules on data/login_logs.csv and checks the same 6 alerts as the Python version. */
class SampleDataTest {

    private static List<Alert> alerts;

    @BeforeAll
    static void loadSampleData() throws IOException {
        List<LoginEvent> logs = LogReader.read(Path.of("data/login_logs.csv"));
        assertEquals(16, logs.size());
        alerts = Detector.detectAll(logs);
    }

    @Test
    void findsSixAlertsInTotal() {
        assertEquals(6, alerts.size());
    }

    @Test
    void bruteForceFoundForThreeIps() {
        List<String> ips = alerts.stream()
                .filter(a -> a.type().equals(Alert.BRUTE_FORCE))
                .map(Alert::ip)
                .toList();

        assertEquals(3, ips.size());
        assertTrue(ips.containsAll(List.of("192.168.1.10", "172.16.0.99", "10.0.0.20")));
    }

    @Test
    void suspiciousSuccessFoundForSylviaAndMary() {
        List<String> users = alerts.stream()
                .filter(a -> a.type().equals(Alert.SUSPICIOUS_SUCCESS))
                .map(Alert::user)
                .toList();

        assertEquals(List.of("sylvia", "mary"), users);
    }

    @Test
    void sharedIpUsedByFourUsers() {
        Alert alert = alerts.stream()
                .filter(a -> a.type().equals(Alert.MULTIPLE_USERS))
                .findFirst()
                .orElseThrow();

        assertEquals("10.0.0.20", alert.ip());
        assertEquals(4, alert.userCount());
    }
}
