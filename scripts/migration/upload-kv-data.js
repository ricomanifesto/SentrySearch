/**
 * Upload KV Data to Cloudflare
 * 
 * Helper script to upload all generated KV data to Cloudflare KV storage
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Configuration
const KV_DATA_DIR = './kv_data';
const NAMESPACE_ID = process.env.CLOUDFLARE_KV_NAMESPACE_ID;

// KV data files to upload
const KV_FILES = [
  {
    file: 'kv_documents.jsonl',
    description: 'Document data with content and metadata'
  },
  {
    file: 'kv_term_indices.jsonl',
    description: 'BM25 term indices for keyword search'
  },
  {
    file: 'kv_company_terms.jsonl',
    description: 'Company-specific term rankings'
  },
  {
    file: 'kv_metadata.jsonl',
    description: 'Metadata caches for filtering'
  }
];

async function uploadKVData() {
  console.log('🚀 Starting Cloudflare KV data upload...');
  console.log('=' * 50);

  // Check if namespace ID is provided
  if (!NAMESPACE_ID) {
    console.error('❌ CLOUDFLARE_KV_NAMESPACE_ID environment variable not set');
    console.log('💡 Get your namespace ID by running: wrangler kv:namespace list');
    process.exit(1);
  }

  // Check if wrangler is installed
  try {
    execSync('wrangler --version', { stdio: 'ignore' });
  } catch (error) {
    console.error('❌ Wrangler CLI not found. Install with: npm install -g wrangler');
    process.exit(1);
  }

  // Check if KV data directory exists
  if (!fs.existsSync(KV_DATA_DIR)) {
    console.error(`❌ KV data directory not found: ${KV_DATA_DIR}`);
    console.log('💡 Run the KV migration script first: python kv_migration.py');
    process.exit(1);
  }

  console.log(`📁 Using namespace ID: ${NAMESPACE_ID}`);
  console.log(`📂 Data directory: ${KV_DATA_DIR}`);

  let totalUploaded = 0;
  let totalErrors = 0;

  // Upload each KV file
  for (const kvFile of KV_FILES) {
    const filePath = path.join(KV_DATA_DIR, kvFile.file);
    
    console.log(`\n📤 Uploading ${kvFile.file}...`);
    console.log(`   ${kvFile.description}`);

    // Check if file exists
    if (!fs.existsSync(filePath)) {
      console.error(`   ❌ File not found: ${filePath}`);
      totalErrors++;
      continue;
    }

    // Get file stats
    const stats = fs.statSync(filePath);
    const fileSizeKB = (stats.size / 1024).toFixed(2);
    console.log(`   📊 File size: ${fileSizeKB} KB`);

    // Count number of entries
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.trim().split('\n').filter(line => line.trim());
      console.log(`   📋 Entries: ${lines.length}`);

      // Upload to Cloudflare KV
      const command = `wrangler kv:bulk put "${filePath}" --namespace-id="${NAMESPACE_ID}"`;
      console.log(`   🔄 Executing: ${command}`);

      try {
        const output = execSync(command, { 
          encoding: 'utf8',
          stdio: 'pipe'
        });
        
        console.log(`   ✅ Upload successful`);
        console.log(`   📤 Response: ${output.trim()}`);
        totalUploaded++;

      } catch (uploadError) {
        console.error(`   ❌ Upload failed: ${uploadError.message}`);
        totalErrors++;
      }

    } catch (readError) {
      console.error(`   ❌ Failed to read file: ${readError.message}`);
      totalErrors++;
    }
  }

  // Summary
  console.log('\n' + '=' * 50);
  console.log('📊 Upload Summary');
  console.log('=' * 50);
  console.log(`✅ Successful uploads: ${totalUploaded}`);
  console.log(`❌ Failed uploads: ${totalErrors}`);
  console.log(`📁 Total files processed: ${KV_FILES.length}`);

  if (totalErrors === 0) {
    console.log('\n🎉 All KV data uploaded successfully!');
    console.log('\n🔄 Next steps:');
    console.log('  1. Deploy your Worker: wrangler deploy');
    console.log('  2. Test the API endpoints');
    console.log('  3. Update your Python client');
  } else {
    console.log('\n⚠️  Some uploads failed. Check the errors above.');
    process.exit(1);
  }
}

// Validation function to check KV data format
function validateKVData() {
  console.log('🔍 Validating KV data format...');

  for (const kvFile of KV_FILES) {
    const filePath = path.join(KV_DATA_DIR, kvFile.file);
    
    if (!fs.existsSync(filePath)) {
      console.error(`❌ Missing file: ${filePath}`);
      continue;
    }

    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.trim().split('\n');

      for (let i = 0; i < Math.min(lines.length, 3); i++) {
        const line = lines[i].trim();
        if (line) {
          const entry = JSON.parse(line);
          
          if (!entry.key || !entry.value) {
            console.error(`❌ Invalid KV format in ${kvFile.file}, line ${i + 1}: missing key or value`);
            continue;
          }

          console.log(`✅ ${kvFile.file}: Valid format (sample key: ${entry.key})`);
          break;
        }
      }

    } catch (error) {
      console.error(`❌ Failed to validate ${kvFile.file}: ${error.message}`);
    }
  }
}

// Helper function to show usage
function showUsage() {
  console.log('📋 Cloudflare KV Upload Script');
  console.log('');
  console.log('Usage:');
  console.log('  CLOUDFLARE_KV_NAMESPACE_ID=your-namespace-id node upload-kv-data.js');
  console.log('');
  console.log('Options:');
  console.log('  --validate    Validate KV data format without uploading');
  console.log('  --help        Show this help message');
  console.log('');
  console.log('Prerequisites:');
  console.log('  1. Install wrangler: npm install -g wrangler');
  console.log('  2. Login to Cloudflare: wrangler login');
  console.log('  3. Create KV namespace: wrangler kv:namespace create "SENTRY_KV"');
  console.log('  4. Run KV migration: python kv_migration.py');
}

// Main execution
async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help')) {
    showUsage();
    return;
  }

  if (args.includes('--validate')) {
    validateKVData();
    return;
  }

  await uploadKVData();
}

// Handle errors
process.on('unhandledRejection', (error) => {
  console.error('❌ Unhandled error:', error);
  process.exit(1);
});

// Run the script
main().catch(console.error);