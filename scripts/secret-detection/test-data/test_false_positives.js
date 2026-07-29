// Test Case 2: JavaScript config with ONLY placeholder / false-positive values
// Expected result: 0 findings above MEDIUM — all should be filtered as false positives
//
// The scanner must NOT alert on these patterns because:
//   - Values reference environment variables (process.env.*)
//   - Values are template placeholders (YOUR_API_KEY_HERE, changeme)
//   - Values are all-same-character strings (xxxx)

const config = {
    // SAFE: environment variable reference — not a hardcoded secret
    apiKey: process.env.API_KEY,
    stripeKey: process.env.STRIPE_SECRET_KEY,

    // SAFE: explicit placeholder text — clearly not a real secret
    githubToken: "YOUR_GITHUB_TOKEN_HERE",
    slackToken: "xoxb-YOUR-SLACK-TOKEN",

    // SAFE: documentation example — low entropy repeated characters
    examplePassword: "xxxxxxxxxxxxxxxxxxxx",
    sampleApiKey: "aaaabbbbccccddddeeee",

    // SAFE: template variable syntax used in CI/CD config templates
    azureClientSecret: "${AZURE_CLIENT_SECRET}",
    awsAccessKey: "{{AWS_ACCESS_KEY_ID}}",

    // SAFE: numeric-only value — not a secret
    sessionTimeout: "3600",

    // SAFE: short value — below minimum length for a real secret
    pin: "1234",
};

module.exports = config;
