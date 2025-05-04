// A simple script to help set up environment variables
const fs = require('fs');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

console.log('\n===== VUWCTF Email Setup =====');
console.log('This script will create a .env file with the necessary configuration for email functionality.');
console.log('\nIMPORTANT: You MUST use a Gmail App Password, not your regular Gmail password.');
console.log('\nTo create an App Password for Gmail:');
console.log('1. Make sure 2-factor authentication is enabled on your Google account');
console.log('   Go to: https://myaccount.google.com/security > 2-Step Verification');
console.log('2. Go to: https://myaccount.google.com/apppasswords');
console.log('3. Select "Mail" as the app and "Other (Custom name)" as the device');
console.log('4. Enter "VUWCTF Website" as the name');
console.log('5. Click "Generate"');
console.log('6. Copy the 16-character password (spaces will be removed automatically)');
console.log('\nCommon issues:');
console.log('- If you\'re using a Google Workspace account, your admin might need to enable API access');
console.log('- Make sure you\'re using the EXACT same email address (vuwctf@gmail.com)');
console.log('============================\n');

rl.question('Enter the Gmail App Password for vuwctf@gmail.com: ', (password) => {
  // Remove any spaces that might have been copied from Google's display
  const cleanPassword = password.replace(/\s+/g, '');
  
  const envContent = `# Environment Variables
# Created on ${new Date().toISOString()}
# DO NOT COMMIT THIS FILE TO VERSION CONTROL

# Gmail App Password for vuwctf@gmail.com
EMAIL_PASSWORD=${cleanPassword}
`;

  fs.writeFile('.env', envContent, (err) => {
    if (err) {
      console.error('Error writing .env file:', err);
    } else {
      console.log('\n✅ .env file created successfully!');
      console.log('Your email settings are now configured.');
      console.log('\n⚠️  IMPORTANT: Keep this file secure and do not commit it to version control.');
      console.log('   The .gitignore file has been set up to exclude it.');
      console.log('\n➡️  Next steps:');
      console.log('   1. Restart your server: npm start');
      console.log('   2. Test the contact form');
    }
    rl.close();
  });
}); 