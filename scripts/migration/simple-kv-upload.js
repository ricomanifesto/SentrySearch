#!/usr/bin/env node

const fs = require('fs');
const { execSync } = require('child_process');

const NAMESPACE_ID = "f97c6c83f96f4b548307ccb1ffaa2668";

async function uploadFile(filename, description) {
  console.log(`\n📤 Uploading ${filename}...`);
  console.log(`   ${description}`);
  
  if (!fs.existsSync(`kv_data/${filename}`)) {
    console.error(`   ❌ File not found: kv_data/${filename}`);
    return false;
  }
  
  try {
    const content = fs.readFileSync(`kv_data/${filename}`, 'utf8');
    const lines = content.trim().split('\n').filter(line => line.trim());
    
    console.log(`   📋 Processing ${lines.length} entries...`);
    
    let successCount = 0;
    let errorCount = 0;
    
    for (let i = 0; i < Math.min(lines.length, 10); i++) { // Upload first 10 entries as test
      try {
        const entry = JSON.parse(lines[i]);
        const key = entry.key;
        const value = JSON.stringify(entry.value);
        
        // Write to temp file
        const tempFile = `/tmp/kv_temp_${i}.json`;
        fs.writeFileSync(tempFile, value);
        
        // Upload using wrangler
        const cmd = `wrangler kv key put "${key}" --namespace-id="${NAMESPACE_ID}" --path="${tempFile}" --remote`;
        execSync(cmd, { stdio: 'pipe' });
        
        // Clean up
        fs.unlinkSync(tempFile);
        
        successCount++;
        if (i % 5 === 0) {
          console.log(`   ⏳ Uploaded ${i + 1}/${Math.min(lines.length, 10)} entries...`);
        }
        
      } catch (error) {
        console.error(`   ❌ Failed to upload entry ${i}: ${error.message}`);
        errorCount++;
      }
    }
    
    console.log(`   ✅ Upload complete: ${successCount} successful, ${errorCount} failed`);
    return errorCount === 0;
    
  } catch (error) {
    console.error(`   ❌ Failed to read file: ${error.message}`);
    return false;
  }
}

async function main() {
  console.log('🚀 Simple KV Upload Script');
  console.log('='.repeat(50));
  console.log(`📁 Using namespace: ${NAMESPACE_ID}`);
  
  const files = [
    { file: 'kv_metadata.jsonl', desc: 'Metadata caches (small file first)' },
    { file: 'kv_company_terms.jsonl', desc: 'Company-specific terms' },
  ];
  
  for (const fileInfo of files) {
    const success = await uploadFile(fileInfo.file, fileInfo.desc);
    if (!success) {
      console.error(`\n❌ Upload failed for ${fileInfo.file}`);
      process.exit(1);
    }
  }
  
  console.log('\n🎉 KV upload test completed successfully!');
  console.log('\n💡 Once working, you can upload the larger files:');
  console.log('   - kv_documents.jsonl (107 entries)');
  console.log('   - kv_term_indices.jsonl (1827 entries)');
}

main().catch(console.error);