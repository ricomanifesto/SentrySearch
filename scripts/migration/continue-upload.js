#!/usr/bin/env node

const fs = require('fs');
const { execSync } = require('child_process');

const NAMESPACE_ID = "f97c6c83f96f4b548307ccb1ffaa2668";

async function continueTermIndicesUpload() {
  console.log('🔄 Continuing term indices upload from where we left off...');
  
  const filename = 'kv_term_indices.jsonl';
  const startIndex = 370; // Continue from approximately where we left off
  const batchSize = 30;   // Increase batch size for faster upload
  
  if (!fs.existsSync(`kv_data/${filename}`)) {
    console.error(`❌ File not found: kv_data/${filename}`);
    return false;
  }
  
  const content = fs.readFileSync(`kv_data/${filename}`, 'utf8');
  const lines = content.trim().split('\n').filter(line => line.trim());
  const remainingLines = lines.slice(startIndex);
  
  console.log(`📋 Uploading ${remainingLines.length} remaining term indices...`);
  
  let successCount = 0;
  let errorCount = 0;
  
  for (let batchStart = 0; batchStart < remainingLines.length; batchStart += batchSize) {
    const batch = remainingLines.slice(batchStart, batchStart + batchSize);
    const batchNum = Math.floor(batchStart / batchSize) + 1;
    const totalBatches = Math.ceil(remainingLines.length / batchSize);
    
    console.log(`🔄 Batch ${batchNum}/${totalBatches} (${batch.length} entries)...`);
    
    for (let i = 0; i < batch.length; i++) {
      try {
        const entry = JSON.parse(batch[i]);
        const key = entry.key;
        const value = JSON.stringify(entry.value);
        
        const tempFile = `/tmp/kv_temp_${Date.now()}_${batchStart + i}.json`;
        fs.writeFileSync(tempFile, value);
        
        const cmd = `wrangler kv key put "${key}" --namespace-id="${NAMESPACE_ID}" --path="${tempFile}" --remote`;
        execSync(cmd, { stdio: 'pipe' });
        
        fs.unlinkSync(tempFile);
        successCount++;
        
      } catch (error) {
        errorCount++;
        if (errorCount > 20) {
          console.error(`🛑 Too many errors, stopping`);
          break;
        }
      }
    }
    
    const percentComplete = Math.round(((batchStart + batch.length) / remainingLines.length) * 100);
    console.log(`⏳ Progress: ${batchStart + batch.length}/${remainingLines.length} (${percentComplete}%) - ${successCount} successful, ${errorCount} failed`);
    
    // Quick progress update every 10 batches
    if (batchNum % 10 === 0) {
      console.log(`📊 Milestone: ${batchNum}/${totalBatches} batches completed`);
    }
  }
  
  console.log(`\n✅ Upload complete: ${successCount} successful, ${errorCount} failed`);
  
  // Quick test
  console.log('\n🧪 Testing system after upload...');
  try {
    const testResult = execSync('curl -s https://sentry-search-hybrid.michaelrico124.workers.dev/metadata/companies', { encoding: 'utf8' });
    const data = JSON.parse(testResult);
    console.log(`📊 System test: ${data.companies?.length || 0} companies available`);
  } catch (e) {
    console.log('⚠️ Quick test failed, but upload completed');
  }
  
  return true;
}

continueTermIndicesUpload().catch(console.error);