package com.sylviawang.logdetector;

import java.time.LocalDateTime;

/** One row of the login log: when, who, from which IP, and whether it worked. */
public record LoginEvent(LocalDateTime timestamp, String user, String ipAddress, String status) {

    public boolean isFailed() {
        return "failed".equals(status);
    }

    public boolean isSuccess() {
        return "success".equals(status);
    }
}
