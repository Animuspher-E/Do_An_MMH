const { execSync } = require('child_process');
const path = require('path');

function checkOCSP(certPath) {

    console.log('=== OCSP CHECK CALLED ===');
    console.log('Certificate:', certPath);

    try {
        const issuer = path.join(
            __dirname,
            '../ca-infrastructure/storage/ca-authority/subCA.pem'
        );

        const cmd =
            `openssl ocsp ` +
            `-issuer "${issuer}" ` +
            `-cert "${certPath}" ` +
            `-url http://127.0.0.1:8888 ` +
            `-CAfile "${issuer}"`;

        console.log('Running OCSP command...');
        const output = execSync(cmd).toString();

        console.log('OCSP Response:\n', output);

        if (output.includes(': revoked')) {
            console.log('=== OCSP RESULT: REVOKED ===');

            return {
                valid: false,
                status: 'REVOKED'
            };
        }

        if (output.includes(': good')) {
            console.log('=== OCSP RESULT: GOOD ===');

            return {
                valid: true,
                status: 'GOOD'
            };
        }

        console.log('=== OCSP RESULT: UNKNOWN ===');

        return {
            valid: false,
            status: 'UNKNOWN'
        };

    } catch (err) {

        console.error('=== OCSP ERROR ===');
        console.error(err.message);

        return {
            valid: false,
            status: 'ERROR'
        };
    }
}

module.exports = { checkOCSP };