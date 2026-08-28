const fs = require("fs");

// Name of your text file
const LOG_FILE = "sample-auth.txt";

// Number of failed attempts before we flag an IP
const FAILED_LOGIN_THRESHOLD = 3;


// Read the log file
function readLogFile(file) {
    try {
        return fs.readFileSync(file, "utf8");
    } catch (error) {
        console.error(`Error reading log file: ${error.message}`);
        process.exit(1);
    }
}


// Convert each line of the log into an object
function parseLogs(logData) {
    const lines = logData
        .split("\n")
        .map(line => line.trim())
        .filter(line => line.length > 0);

    return lines.map(line => {
        const parts = line.split(/\s+/);

        return {
            date: parts[0],
            time: parts[1],
            event: parts[2],
            ip: parts[3]
        };
    });
}


// Analyze the login activity
function analyzeLogs(logs) {
    let successfulLogins = 0;
    let failedLogins = 0;

    const failedAttemptsByIP = {};

    logs.forEach(log => {

        // Count successful logins
        if (log.event === "LOGIN_SUCCESS") {
            successfulLogins++;
        }

        // Count failed logins
        if (log.event === "LOGIN_FAILED") {
            failedLogins++;

            // Create a counter for a new IP
            if (!failedAttemptsByIP[log.ip]) {
                failedAttemptsByIP[log.ip] = 0;
            }

            // Increase the failed-login counter
            failedAttemptsByIP[log.ip]++;
        }
    });


    // Find IP addresses with too many failed attempts
    const suspiciousIPs = Object.entries(failedAttemptsByIP)
        .filter(([ip, attempts]) => attempts >= FAILED_LOGIN_THRESHOLD)
        .map(([ip, attempts]) => ({
            ip,
            attempts
        }));


    return {
        totalEvents: logs.length,
        successfulLogins,
        failedLogins,
        failedAttemptsByIP,
        suspiciousIPs
    };
}


// Display the final report
function displayReport(results) {

    console.log("\n========================================");
    console.log("        SECURITY LOG ANALYZER");
    console.log("========================================");

    console.log(`\nTotal events analyzed: ${results.totalEvents}`);

    console.log(`Successful logins: ${results.successfulLogins}`);

    console.log(`Failed logins: ${results.failedLogins}`);


    console.log("\nFailed Login Attempts by IP:");
    console.log("----------------------------------------");

    Object.entries(results.failedAttemptsByIP).forEach(
        ([ip, attempts]) => {

            console.log(
                `${ip} → ${attempts} failed attempt(s)`
            );

        }
    );


    console.log("\nPotential Security Alerts:");
    console.log("----------------------------------------");


    if (results.suspiciousIPs.length === 0) {

        console.log("No suspicious activity detected.");

    } else {

        results.suspiciousIPs.forEach(alert => {

            console.log(
                `⚠ ${alert.ip} generated ${alert.attempts} failed login attempts`
            );

        });

    }

    console.log("\n========================================\n");
}


// Run the program
const logData = readLogFile(LOG_FILE);

const logs = parseLogs(logData);

const results = analyzeLogs(logs);

displayReport(results);
