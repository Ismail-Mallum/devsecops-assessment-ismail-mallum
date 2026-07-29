// Test Case 1: Java service config with multiple real secrets
// Expected findings: AWS_ACCESS_KEY (HIGH), HARDCODED_PASSWORD (HIGH), DB_CONNECTION_STRING (HIGH)

package com.example.countryservice.config;

import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    // BAD: Hardcoded AWS credentials — should be in environment variables or AWS Secrets Manager
    private static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    private static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    // BAD: Hardcoded database password
    private String dbPassword = "SuperSecret123!";

    // BAD: Full JDBC connection string with embedded credentials
    private String datasourceUrl =
        "jdbc:postgresql://prod-db.example.com:5432/countries?user=admin&password=Passw0rd!";

    // BAD: GitHub token committed to source
    private static final String GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";

    public void connect() {
        // Using the hardcoded values — extremely dangerous in production
        System.out.println("Connecting with key: " + AWS_ACCESS_KEY_ID);
    }
}
