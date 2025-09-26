// Register Chart.js plugins
Chart.register(ChartDataLabels);

// Application state
const historyList = [];
let xaiChart;
let shapChart = null;
let confidenceRiskChart = null;
let analysisCount = 0;


// DOM element references
const elements = {
  form: document.getElementById('uploadForm'),
  fileInput: document.getElementById('fileInput'),
  fileName: document.getElementById('fileName'),
  analyzeBtn: document.getElementById('analyzeBtn'),
  exportPdfBtn: document.getElementById('exportPdfBtn'),
  exportCsvBtn: document.getElementById('exportCsvBtn'),
  darkModeToggle: document.getElementById('darkModeToggle'),
  toggleIcon: document.getElementById('toggleIcon'),
  errorMsg: document.getElementById('errorMsg'),
  loadingIndicator: document.getElementById('loadingIndicator'),
  resultSection: document.getElementById('result'),
  historySection: document.getElementById('history'),
  noHistory: document.getElementById('noHistory'),
  pages: {
    dashboard: document.getElementById('page-dashboard'),
    result: document.getElementById('page-result'),
    history: document.getElementById('page-history'),
  },
  navDashboard: document.getElementById('nav-dashboard'),
  navResult: document.getElementById('nav-result'),
  navHistory: document.getElementById('nav-history'),
};

// File handling functions
function handleFileInputChange() {
  const fileInput = elements.fileInput;
  const fileName = elements.fileName;
 
  if (fileInput.files.length > 0) {
    fileName.textContent = fileInput.files[0].name;
    fileName.classList.remove('hidden');
  } else {
    fileName.classList.add('hidden');
  }
}

function preventDefaults(e) {
  e.preventDefault();
  e.stopPropagation();
}

function highlight() {
  const fileInputArea = document.querySelector('.file-input');
  fileInputArea.classList.add('bg-primary', 'bg-opacity-10');
}

function unhighlight() {
  const fileInputArea = document.querySelector('.file-input');
  fileInputArea.classList.remove('bg-primary', 'bg-opacity-10');
}

function handleDrop(e) {
  const dt = e.dataTransfer;
  const files = dt.files;
  elements.fileInput.files = files;
 
  if (files.length > 0) {
    elements.fileName.textContent = files[0].name;
    elements.fileName.classList.remove('hidden');
  }
}

// Initialize drag and drop
function initializeDragAndDrop() {
  const fileInputArea = document.querySelector('.file-input');
 
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    fileInputArea.addEventListener(eventName, preventDefaults, false);
  });
  ['dragenter', 'dragover'].forEach(eventName => {
    fileInputArea.addEventListener(eventName, highlight, false);
  });
  ['dragleave', 'drop'].forEach(eventName => {
    fileInputArea.addEventListener(eventName, unhighlight, false);
  });
  fileInputArea.addEventListener('drop', handleDrop, false);
}

// UI utility functions
function resetUI() {
  elements.errorMsg.classList.add('hidden');
  elements.resultSection.innerHTML = '';
  elements.exportPdfBtn.disabled = true;
  elements.exportCsvBtn.disabled = true;
}

function showError(message) {
  elements.errorMsg.textContent = message;
  elements.errorMsg.classList.remove('hidden');
}

function showLoading(show = true) {
  if (show) {
    elements.analyzeBtn.disabled = true;
    elements.analyzeBtn.classList.add('opacity-60', 'cursor-not-allowed');
    elements.loadingIndicator.classList.remove('hidden');
  } else {
    elements.analyzeBtn.disabled = false;
    elements.analyzeBtn.classList.remove('opacity-60', 'cursor-not-allowed');
    elements.loadingIndicator.classList.add('hidden');
  }
}

// Page navigation
function showPage(page) {
  Object.keys(elements.pages).forEach(p => {
    if (p === page) {
      elements.pages[p].classList.remove('hidden');
    } else {
      elements.pages[p].classList.add('hidden');
    }
  });
 
  [elements.navDashboard, elements.navResult, elements.navHistory].forEach(item => {
    item.setAttribute('aria-current', 'false');
  });
 
  if (page === 'dashboard') {
    elements.navDashboard.setAttribute('aria-current', 'page');
  } else if (page === 'result') {
    elements.navResult.setAttribute('aria-current', 'page');
  } else if (page === 'history') {
    elements.navHistory.setAttribute('aria-current', 'page');
  }
}

// File validation
function validateFile(file) {
  if (!file) {
    return { valid: false, message: 'Please select a file to analyze.' };
  }
  // Only allow PE formats that backend accepts
  if (!file.name.match(/\.(exe)$/i)) {
    return {
      valid: false,
      message: 'Unsupported file type. Please upload an .exe file only'
    };
  }
  return { valid: true };
}

// Analysis function (calls Flask backend)
async function performAnalysis(file) {
  const formData = new FormData();
  formData.append("file", file);
  
  const response = await fetch("http://127.0.0.1:5000/analyze", {
    method: "POST",
    body: formData,
  });
  
  if (!response.ok) {
    throw new Error(`Server error: ${response.status}`);
  }
  
  const data = await response.json();
  
  if (data.error) {
    throw new Error(data.error);
  }
  
  // Add timestamp client-side if not present
  if (!data.timestamp) {
    data.timestamp = new Date().toISOString();
  }
  
  return data;
}

// Enhanced chart functions
// function drawXAIChart(confidence) {
//   const ctx = document.getElementById('xaiChart').getContext('2d');
//   if (xaiChart) xaiChart.destroy();
 
//   xaiChart = new Chart(ctx, {
//     type: 'doughnut',
//     data: {
//       labels: ['Malicious', 'Prediction'],
//       datasets: [{
//         data: [confidence, 1 - confidence],
//         backgroundColor: ['#ce2222ff', '#0c72b5ff'],
//         borderWidth: 0,
//         cutout: '70%',
//       }],
//     },
//     options: {
//       responsive: true,
//       maintainAspectRatio: true,
//       plugins: {
//         legend: {
//           position: 'bottom',
//           labels: {
//             color: '#ddd',
//             font: { weight: '600', family: "'Inter', 'ui-sans-serif', 'system-ui'" }
//           },
//         },
//         datalabels: {
//           color: '#fff',
//           font: { weight: 'bold', size: 14, family: "'Inter', 'ui-sans-serif', 'system-ui'" },
//           formatter: (value, ctx) => {
//             const dataArr = ctx.chart.data.datasets[0].data;
//             const sum = dataArr.reduce((a,b) => a + b, 0);
//             return ((value / sum) * 100).toFixed(1) + '%';
//           },
//         },
//       },
//     },
//     plugins: [ChartDataLabels],
//   });
// }
console.log('drawXAIChart result:', result);

function drawXAIChart(result) {
  const ctx = document.getElementById('xaiChart').getContext('2d');

  if (xaiChart) xaiChart.destroy();

  // Safely extract probabilities from result
  const maliciousProb = typeof result.probability_malicious === 'number' ? result.probability_malicious : 0;
  const benignProb = typeof result.probability_benign === 'number' 
                      ? result.probability_benign 
                      : 1 - maliciousProb;

  console.log("drawXAIChart result:", result);
  console.log("Malicious Probability:", maliciousProb, "Benign Probability:", benignProb);

  xaiChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Malicious Probability', 'Benign Probability'],
      datasets: [{
        data: [maliciousProb, benignProb],
        backgroundColor: ['#ce2222ff', '#0c72b5ff'],
        borderWidth: 0,
        cutout: '70%',
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: 'bottom', 
          align: 'center',
          labels: {
            color: '#ddd',
            font: { weight: '600', family: "'Inter', 'ui-sans-serif', 'system-ui'" },
            boxWidth: 20,
            boxHeight: 20,
            padding: 15, 
            usePointStyle: true
          },
        },
        datalabels: {
          color: '#fff',
          font: { weight: 'bold', size: 14, family: "'Inter', 'ui-sans-serif', 'system-ui'" },
          formatter: (value, ctx) => {
            const dataArr = ctx.chart.data.datasets[0].data;
            const sum = dataArr.reduce((a, b) => a + b, 0);
            return sum > 0 ? ((value / sum) * 100).toFixed(1) + '%' : '0%';
          },
        },
      },
    },
    plugins: [ChartDataLabels],
  });
}



function drawShapChart(shapData) {
  console.log('=== drawShapChart CALLED ===');
  
  const chartContainer = document.getElementById('shapChart');
  if (!chartContainer || !shapData) return;
  
  const ctx = chartContainer.getContext('2d');
  if (shapChart) shapChart.destroy();
  
  // Prepare data for horizontal bar chart
  const features = shapData.top_features.slice(0, 8); // Top 8 features
  const labels = features.map(f => f.feature.replace(/_/g, ' ').replace(/([A-Z])/g, ' $1').trim());
  const values = features.map(f => f.abs_importance); // ✅ Fixed this line
  const colors = features.map(f => f.contribution === 'increases_risk' ? '#ef4444' : '#22c55e');
  
  shapChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Feature Importance',
        data: values,
        backgroundColor: colors,
        borderColor: colors,
        borderWidth: 1,
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        title: {
          display: true,
          text: 'Top Features Influencing Prediction',
          color: '#ddd',
          font: { size: 16, weight: 'bold' }
        }
      },
      scales: {
        x: {
          beginAtZero: true,
          ticks: { color: '#ddd' },
          grid: { color: '#374151' }
        },
        y: {
          ticks: { color: '#ddd', font: { size: 12 } },
          grid: { color: '#374151' }
        }
      }
    }
  });
}


function drawConfidenceRiskChart(confidence, riskScore) {
  const ctx = document.getElementById('confidenceRiskChart').getContext('2d');
  
  if (confidenceRiskChart) confidenceRiskChart.destroy();
  
  confidenceRiskChart = new Chart(ctx, {
    type: 'scatter',
    data: {
      datasets: [{
        label: 'Confidence vs Risk',
        data: [{ x: confidence * 100, y: riskScore }], // convert confidence to percentage
        backgroundColor: '#F59E0B',
        pointRadius: 6,
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: function(context) {
              return `Confidence: ${context.raw.x.toFixed(1)}%, Risk: ${context.raw.y}%`;
            }
          }
        },
        title: {
          display: true,
          text: 'Prediction Confidence vs Risk',
          color: '#ddd',
          font: { size: 16, weight: 'bold' }
        }
      },
      scales: {
        x: {
          title: { display: true, text: 'Prediction Confidence (%)', color: '#ddd', font:{size:15} },
          min: 0,
          max: 100,
          ticks: { color: '#ddd' },
          grid: { color: '#374151' }
        },
        y: {
          title: { display: true, text: 'Risk Score (%)', color: '#ddd', font:{size:15} },
          min: 0,
          max: 100,
          ticks: { color: '#ddd' },
          grid: { color: '#374151' }
        }
      },
      tooltip: {
        callbacks: {
          label: function(context) {
            return `Prediction Confidence: ${context.raw.x.toFixed(1)}%, Risk Score: ${context.raw.y}%`;
          }
        }
      }
    }
  });
}


// Enhanced result display function
function displayResults(result) {
  const resultContainer = elements.resultSection;
  
  // Get threat level styling
  const getThreatStyles = (threatLevel) => {
    const styles = {
      'HIGH': { bg: 'bg-red-900', text: 'text-red-100', border: 'border-red-500' },
      'MEDIUM': { bg: 'bg-orange-900', text: 'text-orange-100', border: 'border-orange-500' },
      'LOW': { bg: 'bg-yellow-900', text: 'text-yellow-100', border: 'border-yellow-500' },
      'MINIMAL': { bg: 'bg-green-900', text: 'text-green-100', border: 'border-green-500' }
    };
    return styles[threatLevel] || styles['MINIMAL'];
  };

  const threatStyles = getThreatStyles(result.threat_level);
  
  resultContainer.innerHTML = `
    <div class="space-y-6">
      <!-- Main Results Card -->
      <div class="bg-gray-800 rounded-lg p-6 border ${threatStyles.border}">
        <div class="flex justify-between items-start mb-4">
          <h3 class="text-xl font-bold text-white">${result.filename}</h3>
          <div class="text-right">
            <span class="inline-block px-3 py-1 rounded-full text-sm font-semibold ${threatStyles.bg} ${threatStyles.text}">
              ${result.threat_level}
            </span>
          </div>
        </div>
        
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
          <!-- Malicious -->
          <div class="text-center">
            <div class="text-2xl font-bold ${result.verdict === 'suspicious' ? 'text-red-400' : 'text-green-400'}">
              ${(result.probability_malicious * 100).toFixed(1)}%
            </div>
            <div class="text-sm text-gray-400">Malicious Probability</div>
          </div>

          <!-- Risk Score -->
          <div class="text-center">
            <div class="text-2xl font-bold text-blue-400">${result.risk_score != null ? result.risk_score + '%' : 'N/A'}</div>
            <div class="text-sm text-gray-400">Risk Score</div>
          </div>

          <!-- Benign -->
          <div class="text-center">
            <div class="text-2xl font-bold text-green-400">${((1 - result.probability_malicious) * 100).toFixed(1)}%</div>
            <div class="text-sm text-gray-400">Prediction Confidence</div>
          </div>

          <!-- Processing Time -->
          <div class="text-center">
            <div class="text-sm font-bold text-gray-400" style="margin-bottom: 12px;font-size: 25px;">${result.analysis_metadata?.processing_time != null ? result.analysis_metadata.processing_time + 's' : 'N/A'}</div>
            <div class="text-sm text-gray-400">Processing Time</div>
          </div>
        </div>



        <div class="text-center">
          <span class="inline-block px-4 py-2 rounded-full text-lg font-bold ${
            result.verdict === 'suspicious' ? 'bg-red-900 text-red-100' : 'bg-green-900 text-green-100'
          }">
            ${result.verdict.toUpperCase()}
          </span>
        </div>
      </div>

      <!-- Model Predictions -->
      ${result.model_predictions ? `
      <div class="bg-gray-800 rounded-lg p-6">
        <h4 class="text-lg font-semibold text-white mb-4">Model Breakdown</h4>
        <div class="grid gap-3">
          ${Object.entries(result.model_predictions).map(([modelName, pred]) => `
            <div class="flex justify-between items-center p-3 bg-gray-700 rounded">
              <span class="font-medium text-gray-300">${modelName.toUpperCase()}</span>
              <div class="text-right">
                <span class="font-bold ${pred.prediction === 1 ? 'text-red-400' : 'text-green-400'}">
                  ${pred.prediction === 1 ? 'SUSPICIOUS' : 'CLEAN'}
                </span>
                <span class="text-sm text-gray-400 ml-2">${(pred.confidence * 100).toFixed(1)}%</span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
      ` : ''}

      <!-- SHAP Explanation -->
      ${result.explanation ? `
      <div class="bg-gray-800 rounded-lg p-6">
        <h4 class="text-lg font-semibold text-white mb-4">AI Explanation</h4>
        
        <!-- Feature Importance Chart -->
        <div class="mb-6">
          <canvas id="shapChart" height="300"></canvas>
        </div>
        
        <!-- Text Explanation -->
        <div class="bg-gray-700 rounded p-4 mb-4">
          <h5 class="font-semibold text-gray-300 mb-2">Why this prediction?</h5>
          <div class="text-gray-300 whitespace-pre-line text-sm">
            ${result.explanation.prediction_explanation || 'No detailed explanation available.'}
          </div>
        </div>
        
        <!-- Top Features List -->
        <div class="space-y-2">
          <h5 class="font-semibold text-gray-300">Key Features:</h5>
          ${result.explanation.top_features.slice(0, 5).map(feature => `
            <div class="flex justify-between items-center p-2 bg-gray-700 rounded text-sm">
              <span class="text-gray-300">${feature.feature.replace(/_/g, ' ')}</span>
              <div class="text-right">
                <span class="font-bold ${feature.contribution === 'increases_risk' ? 'text-red-400' : 'text-green-400'}">
                  ${feature.contribution === 'increases_risk' ? '↑ Risk' : '↓ Risk'}
                </span>
                <span class="text-gray-400 ml-2">${Math.abs(feature.importance).toFixed(3)}</span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
      ` : ''}

      <!-- Technical Details -->
      <div class="bg-gray-800 rounded-lg p-6">
        <h4 class="text-lg font-semibold text-white mb-4">Technical Details</h4>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm" style="width:auto;">
          <div>
            <span class="text-gray-400">File Hash:</span>
            <span class="text-gray-300 font-mono break-all overflow-x-auto block">${result.file_hash}</span>
          </div>
          <div>
            <span class="text-gray-400">File Size:</span>
            <span class="text-gray-300">${formatFileSize(result.file_size)}</span>
          </div>
          <div>
            <span class="text-gray-400">Analysis Time:</span>
            <span class="text-gray-300">${new Date(result.timestamp).toLocaleString()}</span>
          </div>
          <div>
            <span class="text-gray-400">Features Analyzed:</span>
            <span class="text-gray-300">${result.analysis_metadata?.feature_count || 'N/A'}</span>
          </div>
        </div>
      </div>
    </div>
  `;

  // Draw SHAP chart if explanation data is available
  if (result.explanation && result.explanation.top_features) {
    // Wait for the DOM to update, then draw the chart
    setTimeout(() => {
      drawShapChart(result.explanation);
    }, 100);
  }
}

// Utility function to format file size
function formatFileSize(bytes) {
  if (!bytes) return 'Unknown';
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// History management with enhanced display
function updateHistoryUI() {
  if (historyList.length === 0) {
    elements.noHistory.style.display = 'block';
    elements.historySection.innerHTML = '';
  } else {
    elements.noHistory.style.display = 'none';
    elements.historySection.innerHTML = historyList.map(item => `
      <li class="history-item bg-gray-800 rounded-lg p-4 mb-3">
        <div class="flex justify-between items-start mb-2">
          <span class="font-semibold text-white" style="margin-right: 50px;">${item.filename}</span>
          <span class="text-xs text-gray-400">${new Date(item.timestamp).toLocaleString()}</span>
        </div>
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-3">
            <span class="inline-block px-2 py-1 rounded-full text-xs font-semibold ${
              item.verdict === 'suspicious' ? 'bg-red-900 text-red-100' : 'bg-green-900 text-green-100'
            }">
              ${item.verdict.toUpperCase()}
            </span>
            ${item.threat_level ? `
              <span class="inline-block px-2 py-1 rounded text-xs font-medium bg-gray-700 text-gray-300">
                ${item.threat_level}
              </span>
            ` : ''}
          </div>
          <div class="text-right text-sm">
            <div class="text-gray-300">Risk: ${item.risk_score || 'N/A'}%</div>
            <div class="text-gray-400 text-xs">Confidence: ${(item.confidence * 100).toFixed(1)}%</div>
          </div>
        </div>
      </li>
    `).join('');
  }
}

function addToHistory(result) {
  // historyList.unshift(result);
  // if (historyList.length > 10) historyList.pop(); // Increased history size
  // updateHistoryUI();
  // Store result in history array
  historyList.unshift(result); 

  // Update the UI
  updateHistoryUI();

  // === Update total analyses counter ===
  const historyCountEl = document.getElementById('historyCount');
  if (historyCountEl) {
    historyCountEl.textContent = parseInt(historyCountEl.textContent || 0) + 1;
  }
}

// Enhanced export functions
function exportToPDF() {
  if (historyList.length === 0) {
    showError('No analysis results to export.');
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  
  // Add title
  doc.setFontSize(20);
  doc.text("Malware Analysis Report", 10, 20);
  
  // Add generation date
  doc.setFontSize(12);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 10, 35);
  
  let yPosition = 50;
  
  historyList.forEach((result, index) => {
    if (yPosition > 250) {
      doc.addPage();
      yPosition = 20;
    }
    
    doc.setFontSize(14);
    doc.text(`Analysis ${index + 1}: ${result.filename}`, 10, yPosition);
    yPosition += 10;
    
    doc.setFontSize(10);
    doc.text(`Verdict: ${result.verdict.toUpperCase()}`, 15, yPosition);
    yPosition += 7;
    doc.text(`Risk Score: ${result.risk_score || 'N/A'}%`, 15, yPosition);
    yPosition += 7;
    doc.text(`Confidence: ${(result.confidence * 100).toFixed(1)}%`, 15, yPosition);
    yPosition += 7;
    doc.text(`Threat Level: ${result.threat_level || 'N/A'}`, 15, yPosition);
    yPosition += 7;
    doc.text(`Timestamp: ${new Date(result.timestamp).toLocaleString()}`, 15, yPosition);
    yPosition += 15;
  });
  
  doc.save("malware_analysis_report.pdf");
}

function exportToCSV() {
  if (historyList.length === 0) {
    showError('No analysis results to export.');
    return;
  }

  let csv = 'Filename,Verdict,Risk Score,Confidence,Threat Level,Detected By,Timestamp\n';
  historyList.forEach(data => {
    csv += `"${data.filename}","${data.verdict}","${data.risk_score || 'N/A'}","${(data.confidence * 100).toFixed(1)}","${data.threat_level || 'N/A'}","${data.detected_by}","${data.timestamp}"\n`;
  });
  
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.hidden = true;
  a.href = url;
  a.download = 'malware_analysis_results.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// Theme management
function toggleDarkMode() {
  if (elements.darkModeToggle.checked) {
    document.documentElement.classList.add('dark');
    document.body.classList.remove('light-mode');
    document.body.classList.add('dark-mode');
    elements.toggleIcon.textContent = '🌙';
  } else {
    document.documentElement.classList.remove('dark');
    document.body.classList.remove('dark-mode');
    document.body.classList.add('light-mode');
    elements.toggleIcon.textContent = '🌞';
  }
}

function initializeDarkMode() {
  if (document.documentElement.classList.contains('dark')) {
    elements.darkModeToggle.checked = true;
    elements.toggleIcon.textContent = '🌙';
    document.body.classList.add('dark-mode');
  } else {
    elements.darkModeToggle.checked = false;
    elements.toggleIcon.textContent = '🌞';
    document.body.classList.add('light-mode');
  }
}

// Main form submission handler
async function handleFormSubmission(e) {
  e.preventDefault();
  resetUI();
  
  const file = elements.fileInput.files[0];
  const validation = validateFile(file);
 
  if (!validation.valid) {
    showError(validation.message);
    elements.fileInput.focus();
    return;
  }
  
  showLoading(true);
  
  try {
    const result = await performAnalysis(file);
   
    // Show result page
    showPage('result');
    
    // Display enhanced results
    displayResults(result);
   
    // Draw confidence chart
    // drawXAIChart(parseFloat(result.confidence));
    drawXAIChart(result);

    // Draw Confidence vs Risk scatter plot
    drawConfidenceRiskChart(parseFloat(result.confidence), result.risk_score);
   
    // Add to history
    addToHistory(result);
   
    // Enable export buttons
    elements.exportPdfBtn.disabled = false;
    elements.exportCsvBtn.disabled = false;
   
  } catch (error) {
    showError('Analysis failed: ' + error.message);
    console.error('Analysis error:', error);
  } finally {
    showLoading(false);
  }
}

// Event listeners setup
function setupEventListeners() {
  elements.fileInput.addEventListener('change', handleFileInputChange);
  elements.form.addEventListener('submit', handleFormSubmission);
  elements.navDashboard.addEventListener('click', () => showPage('dashboard'));
  elements.navResult.addEventListener('click', () => showPage('result'));
  elements.navHistory.addEventListener('click', () => showPage('history'));
  elements.exportPdfBtn.addEventListener('click', exportToPDF);
  elements.exportCsvBtn.addEventListener('click', exportToCSV);
  elements.darkModeToggle.addEventListener('change', toggleDarkMode);
}

// Application initialization
function initializeApp() {
  setupEventListeners();
  initializeDragAndDrop();
  initializeDarkMode();
  showPage('dashboard');
  updateHistoryUI();
}

window.addEventListener('DOMContentLoaded', initializeApp);