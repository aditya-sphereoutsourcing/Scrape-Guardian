
async function analyzeWebsite() {
    const url = document.getElementById('url').value;
    const result = document.getElementById('result');
    result.innerHTML = '<div class="loading">Analyzing your website...</div>';
    
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url})
        });
        const data = await response.json();
        
        if (data.error) {
            result.innerHTML = `<div id="error">${data.error}</div>`;
        } else {
            result.innerHTML = `
                <div class="score-card">
                    <div class="metric">
                        <h3>Security</h3>
                        <div class="percentage">${data.results.ratings.security}%</div>
                    </div>
                    <div class="metric">
                        <h3>SEO</h3>
                        <div class="percentage">${data.results.ratings.seo}%</div>
                    </div>
                    <div class="metric">
                        <h3>Performance</h3>
                        <div class="percentage">${data.results.ratings.performance}%</div>
                    </div>
                    <div class="metric">
                        <h3>Overall Score</h3>
                        <div class="percentage">${data.results.ratings.overall.toFixed(1)}%</div>
                    </div>
                </div>
                <div style="text-align: center;">
                    <a href="/analysis-report.pdf" target="_blank" class="download-report">Download Detailed Report</a>
                </div>
            `;
        }
    } catch (error) {
        result.innerHTML = `<div id="error">Error: ${error.message}</div>`;
    }
}
