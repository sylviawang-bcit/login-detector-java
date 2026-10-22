package com.sylviawang.logdetector;

/**
 * An alert raised by one of the detection rules.
 * user is null for IP-based rules; userCount is 0 unless the rule counts users.
 */
public record Alert(String type, String ip, String user, int userCount, String message) {

    public static final String BRUTE_FORCE = "Brute Force";
    public static final String SUSPICIOUS_SUCCESS = "Suspicious Login After Multiple Failures";
    public static final String MULTIPLE_USERS = "Suspicious Multiple-User Login Activity";
}
