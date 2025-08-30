// Test script for multi-vendor query generation
import { renderTemplateWithVendor, cqlTemplates } from './src/lib/cql-templates.js';

// Test IOCs
const testIOCs = {
  ipv4: ['192.168.1.100', '10.0.0.50'],
  ipv6: [],
  domains: ['malicious.example.com', 'bad-domain.net'],
  urls: ['http://malicious.example.com/payload'],
  sha256: ['a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456'],
  md5: ['5d41402abc4b2a76b9719d911017c592'],
  emails: ['attacker@malicious.example.com']
};

// Test template (using first available template)
const testTemplate = cqlTemplates[0];

console.log('Testing Multi-Vendor Query Generation');
console.log('=====================================');
console.log(`Using template: ${testTemplate.name}`);
console.log(`Template description: ${testTemplate.description}`);
console.log('');

// Test different vendors
const vendors = [
  { vendorId: 'crowdstrike', moduleId: 'falcon-data-replicator', name: 'CrowdStrike LogScale (CQL)' },
  { vendorId: 'splunk', moduleId: 'splunk-enterprise', name: 'Splunk Enterprise (SPL)' },
  { vendorId: 'sentinel', moduleId: 'sentinel-standard', name: 'Microsoft Sentinel (KQL)' },
  { vendorId: 'logscale', moduleId: 'logscale-standard', name: 'LogScale Self-Hosted (CQL)' }
];

vendors.forEach(vendor => {
  console.log(`--- ${vendor.name} ---`);
  try {
    const result = renderTemplateWithVendor(
      testTemplate,
      testIOCs,
      vendor.vendorId,
      vendor.moduleId
    );
    
    console.log('Generated Query:');
    console.log(result.query);
    console.log('');
    
    if (result.warnings.length > 0) {
      console.log('Warnings:');
      result.warnings.forEach(warning => console.log(`  - ${warning}`));
      console.log('');
    }
    
    console.log('Profile:', result.profile.name);
    console.log('');
    
  } catch (error) {
    console.error(`Error generating query for ${vendor.name}:`, error.message);
    console.log('');
  }
});

console.log('Test completed.');
