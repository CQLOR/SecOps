const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = 3000;

// Serve static files from the current directory
app.use(express.static(path.join(__dirname)));

// Specific route for the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'case_report.html'));
});

// Download endpoint for PDF
app.get('/download/pdf', (req, res) => {
    const file = path.join(__dirname, 'case_report.pdf');
    res.download(file, 'case_report.pdf', (err) => {
        if (err) {
            console.error('Error downloading PDF:', err);
            res.status(404).send('PDF report not found. Please run the python script first.');
        }
    });
});

// Download endpoint for JSON
app.get('/download/json', (req, res) => {
    const file = path.join(__dirname, 'case_report.json');
    res.download(file, 'case_report.json', (err) => {
        if (err) {
            console.error('Error downloading JSON:', err);
            res.status(404).send('JSON report not found. Please run the python script first.');
        }
    });
});

// Download endpoint for CSV
app.get('/download/csv', (req, res) => {
    const file = path.join(__dirname, 'case_report.csv');
    res.download(file, 'case_report.csv', (err) => {
        if (err) {
            console.error('Error downloading CSV:', err);
            res.status(404).send('CSV report not found. Please run the python script first.');
        }
    });
});

// Download endpoint for CSZ (gzipped CSV) - optional file
// (Removed CSZ endpoint — CSV is served via /download/csv)

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log('Press Ctrl+C to stop');
});
