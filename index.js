import express from 'express';
import axios from 'axios';
import * as cheerio from 'cheerio';
import puppeteer from 'puppeteer';
import PDFDocument from 'pdfkit';
import * as cliProgress from 'cli-progress';
import fs from 'fs';

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the Website Analysis API' });
});

async function analyzeWebsite(url) {
  const progressBar = new cliProgress.SingleBar({}, cliProgress.Presets.shades_classic);
  progressBar.start(100, 0);

  const results = {
    securityIssues: [],
    seoIssues: [],
    content: []
  };

  try {
    // Scrape content
    progressBar.update(20);
    const response = await axios.get(url);
    const $ = cheerio.load(response.data);
    results.content = $('article').text();

    // Security analysis
    progressBar.update(40);
    const browser = await puppeteer.launch({ 
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
      headless: 'new'
    });
    const page = await browser.newPage();
    await page.goto(url);

    // Check for HTTPS
    if (!url.startsWith('https')) {
      results.securityIssues.push('Site not using HTTPS');
    }

    // Check for basic security headers
    const securityHeaders = response.headers;
    if (!securityHeaders['x-content-type-options']) {
      results.securityIssues.push('Missing X-Content-Type-Options header');
    }
    if (!securityHeaders['x-frame-options']) {
      results.securityIssues.push('Missing X-Frame-Options header');
    }

    // SEO Analysis using Lighthouse
    progressBar.update(60);
    const lighthouse = (await import('lighthouse')).default; // Dynamic import
    const lighthouseReport = await lighthouse(url, {
      port: (new URL(browser.wsEndpoint())).port,
      output: 'json',
      onlyCategories: ['seo', 'best-practices']
    });

    results.seoIssues = lighthouseReport.lhr.categories.seo.auditRefs
      .filter(audit => audit.score < 0.9)
      .map(audit => audit.title);

    await browser.close();

    // Generate PDF Report
    progressBar.update(80);
    const doc = new PDFDocument();
    const pdfPath = './analysis-report.pdf';
    doc.pipe(fs.createWriteStream(pdfPath));

    doc.fontSize(20).text('Website Analysis Report', { align: 'center' });
    doc.moveDown();
    doc.fontSize(16).text('Security Issues:');
    results.securityIssues.forEach(issue => doc.fontSize(12).text(`• ${issue}`));
    doc.moveDown();
    doc.fontSize(16).text('SEO Issues:');
    results.seoIssues.forEach(issue => doc.fontSize(12).text(`• ${issue}`));

    doc.end();

    progressBar.update(100);
    progressBar.stop();

    return results;
  } catch (error) {
    progressBar.stop();
    console.error('Analysis failed:', error);
    throw error;
  }
}

app.post('/analyze', async (req, res) => {
  try {
    const { url } = req.body;
    const results = await analyzeWebsite(url);
    res.json({
      message: 'Analysis complete',
      results,
      reportPath: 'analysis-report.pdf'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on port ${port}`);
});