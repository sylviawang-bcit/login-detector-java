package com.sylviawang.logdetector;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class DetectorTest {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // Small helper so each test reads like a few log lines
    private static LoginEvent event(String time, String user, String ip, String status) {
        return new LoginEvent(LocalDateTime.parse(time, FMT), user, ip, status);
    }

    @Nested
    @DisplayName("Rule 1: brute force")
    class BruteForce {

        @Test
        void threeFailuresWithinFiveMinutesRaisesOneAlert() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 09:00:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 09:01:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 09:02:00", "test_user", "192.168.1.100", "failed"));

            List<Alert> alerts = Detector.detectBruteForce(logs);

            assertEquals(1, alerts.size());
            assertEquals(Alert.BRUTE_FORCE, alerts.get(0).type());
            assertEquals("192.168.1.100", alerts.get(0).ip());
        }

        @Test
        void twoFailuresDoNotRaiseAlert() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 09:00:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 09:01:00", "test_user", "192.168.1.100", "failed"));

            assertTrue(Detector.detectBruteForce(logs).isEmpty());
        }

        @Test
        void failuresSpreadOverMoreThanFiveMinutesDoNotRaiseAlert() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 09:00:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 09:04:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 09:08:00", "test_user", "192.168.1.100", "failed"));

            assertTrue(Detector.detectBruteForce(logs).isEmpty());
        }

        @Test
        void failureExactlyFiveMinutesLaterIsCounted() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 09:00:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 09:02:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 09:05:00", "test_user", "192.168.1.100", "failed"));

            assertEquals(1, Detector.detectBruteForce(logs).size());
        }

        @Test
        void unsortedInputStillDetected() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 09:02:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 09:00:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 09:01:00", "test_user", "192.168.1.100", "failed"));

            assertEquals(1, Detector.detectBruteForce(logs).size());
        }

        @Test
        void manyFailuresStillGiveOnlyOneAlertPerIp() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 09:00:00", "a", "192.168.1.100", "failed"),
                    event("2026-09-01 09:00:10", "a", "192.168.1.100", "failed"),
                    event("2026-09-01 09:00:20", "a", "192.168.1.100", "failed"),
                    event("2026-09-01 09:00:30", "a", "192.168.1.100", "failed"),
                    event("2026-09-01 09:00:40", "a", "192.168.1.100", "failed"));

            assertEquals(1, Detector.detectBruteForce(logs).size());
        }
    }

    @Nested
    @DisplayName("Rule 2: success after failures")
    class SuspiciousSuccess {

        @Test
        void successAfterThreeFailuresRaisesAlert() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 10:00:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 10:01:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 10:02:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 10:03:00", "test_user", "192.168.1.100", "success"));

            List<Alert> alerts = Detector.detectSuspiciousSuccess(logs);

            assertEquals(1, alerts.size());
            Alert alert = alerts.get(0);
            assertEquals(Alert.SUSPICIOUS_SUCCESS, alert.type());
            assertEquals("test_user", alert.user());
            assertEquals("192.168.1.100", alert.ip());
        }

        @Test
        void oldFailuresOutsideWindowAreIgnored() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 10:00:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 10:01:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 10:02:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 10:20:00", "test_user", "192.168.1.100", "success"));

            assertTrue(Detector.detectSuspiciousSuccess(logs).isEmpty());
        }

        @Test
        void failuresByOtherUsersDoNotCount() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 10:00:00", "user1", "192.168.1.100", "failed"),
                    event("2026-09-01 10:01:00", "user2", "192.168.1.100", "failed"),
                    event("2026-09-01 10:02:00", "user3", "192.168.1.100", "failed"),
                    event("2026-09-01 10:03:00", "user4", "192.168.1.100", "success"));

            assertTrue(Detector.detectSuspiciousSuccess(logs).isEmpty());
        }

        @Test
        void failuresAfterTheSuccessDoNotCount() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 10:00:00", "test_user", "192.168.1.100", "success"),
                    event("2026-09-01 10:01:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 10:02:00", "test_user", "192.168.1.100", "failed"),
                    event("2026-09-01 10:03:00", "test_user", "192.168.1.100", "failed"));

            assertTrue(Detector.detectSuspiciousSuccess(logs).isEmpty());
        }
    }

    @Nested
    @DisplayName("Rule 3: many users from one IP")
    class MultipleUsers {

        @Test
        void threeUsersFromSameIpRaisesAlert() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 12:00:00", "user1", "10.0.0.20", "success"),
                    event("2026-09-01 12:01:00", "user2", "10.0.0.20", "failed"),
                    event("2026-09-01 12:02:00", "user3", "10.0.0.20", "failed"));

            List<Alert> alerts = Detector.detectMultipleUsers(logs);

            assertEquals(1, alerts.size());
            Alert alert = alerts.get(0);
            assertEquals(Alert.MULTIPLE_USERS, alert.type());
            assertEquals("10.0.0.20", alert.ip());
            assertEquals(3, alert.userCount());
            assertNull(alert.user());
        }

        @Test
        void sameUserManyTimesIsNotCountedTwice() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 12:00:00", "user1", "10.0.0.20", "success"),
                    event("2026-09-01 12:01:00", "user1", "10.0.0.20", "success"),
                    event("2026-09-01 12:02:00", "user2", "10.0.0.20", "success"));

            assertTrue(Detector.detectMultipleUsers(logs).isEmpty());
        }

        @Test
        void usersFromDifferentIpsDoNotRaiseAlert() {
            List<LoginEvent> logs = List.of(
                    event("2026-09-01 12:00:00", "user1", "10.0.0.20", "success"),
                    event("2026-09-01 12:01:00", "user2", "10.0.0.21", "success"),
                    event("2026-09-01 12:02:00", "user3", "10.0.0.22", "success"));

            assertTrue(Detector.detectMultipleUsers(logs).isEmpty());
        }
    }

    @Test
    void emptyLogGivesNoAlerts() {
        assertTrue(Detector.detectAll(List.of()).isEmpty());
    }
}
