-- Reports the observed session identity for the job receipt.
SELECT 'result|database|' || current_database();
SELECT 'result|principal|' || current_user;
