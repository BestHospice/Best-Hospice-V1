require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const { GoogleAdsApi } = require('google-ads-api');

const client = new GoogleAdsApi({
  client_id: process.env.GOOGLE_ADS_CLIENT_ID,
  client_secret: process.env.GOOGLE_ADS_CLIENT_SECRET,
  developer_token: process.env.GOOGLE_ADS_DEVELOPER_TOKEN,
});

const customer = client.Customer({
  customer_id: process.env.GOOGLE_ADS_CUSTOMER_ID,
  refresh_token: process.env.GOOGLE_ADS_REFRESH_TOKEN,
});

async function getCampaignPerformance() {
  const campaigns = await customer.query(`
    SELECT
      campaign.id,
      campaign.name,
      campaign.status,
      campaign.bidding_strategy_type,
      metrics.impressions,
      metrics.clicks,
      metrics.cost_micros,
      metrics.conversions,
      metrics.ctr,
      metrics.average_cpc,
      metrics.cost_per_conversion
    FROM campaign
    WHERE segments.date DURING LAST_30_DAYS
      AND campaign.status = 'ENABLED'
    ORDER BY metrics.cost_micros DESC
  `);

  console.log('\n=== CAMPAIGN PERFORMANCE (Last 30 Days) ===\n');
  for (const row of campaigns) {
    const cost = (row.metrics.cost_micros / 1_000_000).toFixed(2);
    const cpc = (row.metrics.average_cpc / 1_000_000).toFixed(2);
    const cpa = row.metrics.conversions > 0
      ? (row.metrics.cost_micros / 1_000_000 / row.metrics.conversions).toFixed(2)
      : 'N/A';

    console.log(`Campaign: ${row.campaign.name}`);
    console.log(`  Status: ${row.campaign.status}`);
    console.log(`  Impressions: ${row.metrics.impressions.toLocaleString()}`);
    console.log(`  Clicks: ${row.metrics.clicks.toLocaleString()}`);
    console.log(`  CTR: ${(row.metrics.ctr * 100).toFixed(2)}%`);
    console.log(`  Avg CPC: $${cpc}`);
    console.log(`  Total Spend: $${cost}`);
    console.log(`  Conversions: ${row.metrics.conversions}`);
    console.log(`  Cost/Conversion: $${cpa}`);
    console.log('');
  }

  return campaigns;
}

async function getKeywordPerformance() {
  const keywords = await customer.query(`
    SELECT
      ad_group_criterion.keyword.text,
      ad_group_criterion.keyword.match_type,
      ad_group_criterion.quality_info.quality_score,
      ad_group_criterion.status,
      campaign.name,
      metrics.impressions,
      metrics.clicks,
      metrics.cost_micros,
      metrics.conversions,
      metrics.ctr,
      metrics.average_cpc
    FROM keyword_view
    WHERE segments.date DURING LAST_30_DAYS
      AND ad_group_criterion.status != 'REMOVED'
    ORDER BY metrics.cost_micros DESC
    LIMIT 50
  `);

  console.log('\n=== TOP KEYWORDS BY SPEND (Last 30 Days) ===\n');
  for (const row of keywords) {
    const cost = (row.metrics.cost_micros / 1_000_000).toFixed(2);
    const cpc = (row.metrics.average_cpc / 1_000_000).toFixed(2);
    const qs = row.ad_group_criterion.quality_info?.quality_score || 'N/A';

    console.log(`Keyword: "${row.ad_group_criterion.keyword.text}" [${row.ad_group_criterion.keyword.match_type}]`);
    console.log(`  Campaign: ${row.campaign.name}`);
    console.log(`  Quality Score: ${qs}/10`);
    console.log(`  Impressions: ${row.metrics.impressions.toLocaleString()}`);
    console.log(`  Clicks: ${row.metrics.clicks.toLocaleString()}`);
    console.log(`  CTR: ${(row.metrics.ctr * 100).toFixed(2)}%`);
    console.log(`  Avg CPC: $${cpc}`);
    console.log(`  Spend: $${cost}`);
    console.log(`  Conversions: ${row.metrics.conversions}`);
    console.log('');
  }

  return keywords;
}

async function getOptimizationRecommendations(campaigns, keywords) {
  console.log('\n=== OPTIMIZATION RECOMMENDATIONS ===\n');

  // Low CTR campaigns
  const lowCTR = campaigns.filter(r => r.metrics.impressions > 100 && r.metrics.ctr < 0.02);
  if (lowCTR.length > 0) {
    console.log('⚠️  LOW CTR CAMPAIGNS (under 2%) — improve ad copy:');
    lowCTR.forEach(r => console.log(`   - ${r.campaign.name}: ${(r.metrics.ctr * 100).toFixed(2)}% CTR`));
    console.log('');
  }

  // High spend, zero conversions
  const wasteful = campaigns.filter(r => r.metrics.cost_micros > 5_000_000 && r.metrics.conversions === 0);
  if (wasteful.length > 0) {
    console.log('🚨 HIGH SPEND, ZERO CONVERSIONS — review or pause:');
    wasteful.forEach(r => {
      const cost = (r.metrics.cost_micros / 1_000_000).toFixed(2);
      console.log(`   - ${r.campaign.name}: $${cost} spent, 0 conversions`);
    });
    console.log('');
  }

  // Low quality score keywords
  const lowQS = keywords.filter(r => {
    const qs = r.ad_group_criterion.quality_info?.quality_score;
    return qs && qs <= 4 && r.metrics.cost_micros > 1_000_000;
  });
  if (lowQS.length > 0) {
    console.log('⚠️  LOW QUALITY SCORE KEYWORDS (≤4/10) — fix landing page relevance or ad copy:');
    lowQS.forEach(r => {
      const qs = r.ad_group_criterion.quality_info?.quality_score;
      const cost = (r.metrics.cost_micros / 1_000_000).toFixed(2);
      console.log(`   - "${r.ad_group_criterion.keyword.text}": QS ${qs}/10, $${cost} spent`);
    });
    console.log('');
  }

  // Broad match keywords with low conversions
  const broadWaste = keywords.filter(r =>
    r.ad_group_criterion.keyword.match_type === 'BROAD' &&
    r.metrics.cost_micros > 3_000_000 &&
    r.metrics.conversions === 0
  );
  if (broadWaste.length > 0) {
    console.log('💡 BROAD MATCH KEYWORDS WITH NO CONVERSIONS — switch to phrase or exact match:');
    broadWaste.forEach(r => {
      const cost = (r.metrics.cost_micros / 1_000_000).toFixed(2);
      console.log(`   - "${r.ad_group_criterion.keyword.text}": $${cost} spent, 0 conversions`);
    });
    console.log('');
  }

  if (lowCTR.length === 0 && wasteful.length === 0 && lowQS.length === 0 && broadWaste.length === 0) {
    console.log('✅ No major issues detected. Campaigns look healthy.');
  }
}

async function main() {
  try {
    console.log('Connecting to Google Ads API...');
    const campaigns = await getCampaignPerformance();
    const keywords = await getKeywordPerformance();
    await getOptimizationRecommendations(campaigns, keywords);
  } catch (err) {
    console.error('Error:', err.message || err);
    if (err.errors) {
      err.errors.forEach(e => console.error(' -', e.message));
    }
  }
}

main();
