package com.sylviawang.logdetector;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class LogReaderTest {

    private static final String HEADER = "timestamp,user,ip_address,status";

    @Test
    void parsesValidLine() {
        List<LoginEvent> events = LogReader.parse(List.of(
                HEADER,
                "2026-09-01 09:00:01,sylvia,192.168.1.10,success"));

        assertEquals(1, events.size());
        LoginEvent e = events.get(0);
        assertEquals(LocalDateTime.of(2026, 9, 1, 9, 0, 1), e.timestamp());
        assertEquals("sylvia", e.user());
        assertEquals("192.168.1.10", e.ipAddress());
        assertTrue(e.isSuccess());
    }

    @Test
    void emptyInputGivesEmptyList() {
        assertTrue(LogReader.parse(List.of()).isEmpty());
    }

    @Test
    void headerOnlyGivesEmptyList() {
        assertTrue(LogReader.parse(List.of(HEADER)).isEmpty());
    }

    @Test
    void blankLinesAreSkipped() {
        List<LoginEvent> events = LogReader.parse(List.of(
                HEADER,
                "",
                "2026-09-01 09:00:01,sylvia,192.168.1.10,failed",
                "   "));

        assertEquals(1, events.size());
    }

    @Test
    void wrongHeaderIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> LogReader.parse(List.of("time,name,ip,result")));
    }

    // Each bad line should be rejected with a clear error, not silently skipped
    @ParameterizedTest
    @ValueSource(strings = {
            "2026-09-01 09:00:01,sylvia,192.168.1.10",           // missing a field
            "2026-09-01 09:00:01,sylvia,192.168.1.10,ok",        // unknown status
            "09/01/2026 09:00,sylvia,192.168.1.10,success",      // wrong date format
            "2026-09-01 25:00:00,sylvia,192.168.1.10,success"    // impossible hour
    })
    void badLinesAreRejected(String badLine) {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> LogReader.parse(List.of(HEADER, badLine)));
        assertTrue(error.getMessage().startsWith("Line 2"));
    }

    @Test
    void readsFromFile(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("logs.csv");
        Files.writeString(file, HEADER + "\n2026-09-01 09:00:01,sylvia,192.168.1.10,failed\n");

        assertEquals(1, LogReader.read(file).size());
    }
}
