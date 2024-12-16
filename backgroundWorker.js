const pool = require('./db'); 
const cron = require('node-cron');

// Function to delete expired OTP records
const deleteExpiredOtps = async () => {
  try {
    const deleteQuery = `DELETE FROM userrecovery;`;
    await pool.query(deleteQuery);
    console.log(`Expired OTPs deleted successfully at ${new Date().toISOString()}`);
    console.log(`Number of records deleted: ${deleteQuery.rowCount || 'No rows affected'}`);
  } catch (err) {
    console.error('Error deleting expired OTPs:', err);
  }
};

// Schedule task to run at midnight (00:00) every day, using the server's local time zone
cron.schedule('0 0 * * *', () => {
  console.log('Running deleteExpiredOtps task...');
  deleteExpiredOtps();
});
