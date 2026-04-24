const { analyzeURL } = require('./analyzer');

async function test() {
    console.log("Testing Analyzer...");
    const urls = [
        "https://google.com",
        "http://192.168.1.1/login-verify-account",
        "https://secure-login-update.bit.ly/wp-content/cmd",
        "https://amazon.com"
    ];

    for (const url of urls) {
        console.log(`\nURL: ${url}`);
        const result = await analyzeURL(url);
        console.log(`Score: ${result.score}`);
        console.log(`Status: ${result.status}`);
        console.log(`Host Info: ${result.hostInfo ? result.hostInfo.isp : 'N/A'}`);
        console.log(`Details: ${result.details.length} factors found.`);
    }
}

test();
