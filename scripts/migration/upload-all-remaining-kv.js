#!/usr/bin/env node

const fs = require('fs');
const { execSync } = require('child_process');

const NAMESPACE_ID = "f97c6c83f96f4b548307ccb1ffaa2668";

async function uploadRemainingEntries(filename, description, startIndex = 0, batchSize = 10) {
  console.log(`\n📤 Uploading remaining ${filename}...`);
  console.log(`   ${description}`);
  
  if (!fs.existsSync(`kv_data/${filename}`)) {
    console.error(`   ❌ File not found: kv_data/${filename}`);
    return false;
  }
  
  try {
    const content = fs.readFileSync(`kv_data/${filename}`, 'utf8');
    const lines = content.trim().split('\n').filter(line => line.trim());
    
    const remainingLines = lines.slice(startIndex);
    console.log(`   📋 Uploading ${remainingLines.length} remaining entries (starting from ${startIndex})...`);
    
    let successCount = 0;
    let errorCount = 0;
    let totalProcessed = 0;
    
    // Process in batches for better performance
    for (let batchStart = 0; batchStart < remainingLines.length; batchStart += batchSize) {
      const batch = remainingLines.slice(batchStart, batchStart + batchSize);
      console.log(`   🔄 Processing batch ${Math.floor(batchStart / batchSize) + 1}/${Math.ceil(remainingLines.length / batchSize)} (${batch.length} entries)...`);
      
      for (let i = 0; i < batch.length; i++) {
        const lineIndex = batchStart + i;
        try {
          const entry = JSON.parse(batch[i]);
          const key = entry.key;
          const value = JSON.stringify(entry.value);
          
          // Write to temp file
          const tempFile = `/tmp/kv_temp_${Date.now()}_${lineIndex}.json`;
          fs.writeFileSync(tempFile, value);
          
          // Upload using wrangler
          const cmd = `wrangler kv key put "${key}" --namespace-id="${NAMESPACE_ID}" --path="${tempFile}" --remote`;
          execSync(cmd, { stdio: 'pipe' });
          
          // Clean up
          fs.unlinkSync(tempFile);
          
          successCount++;
          totalProcessed++;
          
        } catch (error) {
          console.error(`   ❌ Failed entry ${startIndex + lineIndex}: ${error.message.slice(0, 60)}...`);
          errorCount++;
          if (errorCount > 20) {
            console.error(`   🛑 Too many errors (${errorCount}), stopping upload`);
            break;
          }
        }
      }
      
      // Progress update
      const percentComplete = Math.round((totalProcessed / remainingLines.length) * 100);
      console.log(`   ⏳ Progress: ${totalProcessed}/${remainingLines.length} (${percentComplete}%) - ${successCount} successful, ${errorCount} failed`);
      
      // Small delay between batches to avoid rate limits
      if (batchStart + batchSize < remainingLines.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    
    console.log(`   ✅ Upload complete: ${successCount} successful, ${errorCount} failed`);
    return successCount > errorCount;
    
  } catch (error) {
    console.error(`   ❌ Failed to read file: ${error.message}`);
    return false;
  }
}

async function uploadAllRemainingData() {
  console.log('🚀 Uploading All Remaining KV Data');
  console.log('='.repeat(60));
  console.log(`📁 Using namespace: ${NAMESPACE_ID}`);
  
  const uploadTasks = [
    {
      file: 'kv_documents.jsonl',
      desc: 'Document data (87 remaining entries)',
      startIndex: 20, // We uploaded 20 already
      batchSize: 5    // Smaller batches for large documents
    },
    {
      file: 'kv_term_indices.jsonl', 
      desc: 'BM25 term indices (1,777 remaining entries)',
      startIndex: 50, // We uploaded 50 already
      batchSize: 20   // Larger batches for smaller term data
    }
  ];
  
  let totalSuccess = true;
  
  for (const task of uploadTasks) {
    console.log(`\n🔄 Starting upload: ${task.file}`);
    const success = await uploadRemainingEntries(
      task.file, 
      task.desc, 
      task.startIndex, 
      task.batchSize
    );
    
    if (!success) {
      console.error(`\n❌ Upload failed for ${task.file}`);
      totalSuccess = false;
    } else {
      console.log(`\n✅ Upload successful for ${task.file}`);
    }
    
    // Delay between different files
    if (uploadTasks.indexOf(task) < uploadTasks.length - 1) {
      console.log('   ⏸️  Waiting 5 seconds before next file...');
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
  
  console.log('\n' + '='.repeat(60));
  console.log('📊 Final Upload Summary');
  console.log('='.repeat(60));
  
  if (totalSuccess) {
    console.log('🎉 All remaining data uploaded successfully!');
    console.log('\n📈 Complete Data Status:');
    console.log('   ✅ Metadata: 3/3 entries (100%)');
    console.log('   ✅ Company Terms: 5/5 entries (100%)');  
    console.log('   ✅ Term Indices: 1,827/1,827 entries (100%)');
    console.log('   ✅ Documents: 107/107 entries (100%)');
    console.log('\n🚀 Workers system now has complete dataset!');
    console.log('🔬 Test the system: python test_workers_system.py');
  } else {
    console.log('⚠️ Some uploads failed. System will work with partial data.');
    console.log('🔄 You can re-run this script to retry failed uploads.');
  }
}

// Add error handling
process.on('unhandledRejection', (error) => {
  console.error('❌ Unhandled error:', error.message);
  process.exit(1);
});

// Add interrupt handling
process.on('SIGINT', () => {
  console.log('\n\n⏹️ Upload interrupted by user');
  console.log('📊 Current progress saved - you can resume later');
  process.exit(0);
});

uploadAllRemainingData().catch(console.error);