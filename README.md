# ScoreRecon

A command-line tool for quickly retrieving and prioritizing CVSS vulnerability scores from Tenable's vulnerability database.

## Description

ScoreRecon extracts Common Vulnerability Scoring System (CVSS) scores for CVE IDs. Currently scrapes from the Tenable website. It helps with analysis of huge texts of reported flaws with zero details on severity, like Apple does on their advisories. Gathers CVSS v2, v3, and v4 scores and sorts them by severity.

## Features

- Extract CVE IDs from arbitrary text input
- Retrieve CVSS v2, v3, and v4 scores from Tenable's vulnerability database
- Sort vulnerabilities by CVSS v3 score (highest severity first)
- Accept input from command line, piped files, or interactive entry
- Rate-limited requests to respect server resources
- Summary statistics of vulnerability findings

## Installation

### Prerequisites

- Python 3.6+
- pip (Python package installer)

### Required Python Packages

```bash
pip install -r requirements.txt 
```

## Usage

### Pipe From File

```bash
cat security_bulletin.txt | python ScoreRecon.py
```

### Interactive Mode

```bash
python ScoreRecon.py
# Then paste your text and press Ctrl+D (Unix/Linux/Mac) or Ctrl+Z followed by Enter (Windows)
```

## Output

ScoreRecon displays results in the terminal and outputs them to a timestamped CSV file. Results are sorted with the highest CVSS v3 scores at the top, making it easy to identify the most critical vulnerabilities first.

### Sample Output

```
ScoreRecon found 3 unique CVE IDs:
1. CVE-2025-31246
2. CVE-2024-8176
3. CVE-2025-31239

Starting vulnerability intelligence gathering for 3 CVEs...

Investigating CVE-2025-31246 (1/3)...
Found scores for CVE-2025-31246:
  CVSS v2 Base Score: 7.5
  CVSS v3 Base Score: 9.8

[...]

--- SUMMARY (sorted by CVSS v3 score, descending) ---
CVE ID          CVSS v2    CVSS v3    CVSS v4   
---------------------------------------------
CVE-2025-31246  7.5        9.8        N/A       
CVE-2024-8176   5.0        7.5        N/A       
CVE-2025-31239  1.7        3.3        N/A       

Found 3 CVSS v2 scores, 3 CVSS v3 scores, and 0 CVSS v4 scores
Total CVEs with at least one score: 3/3
```

## How It Works

1. Extracts CVE IDs from user input using regular expressions
2. Queries the Tenable vulnerability database for each CVE
3. Parses the HTML response to extract CVSS scores
4. Converts scores to floating-point numbers for proper sorting
5. Sorts vulnerabilities by CVSS v3 score (descending)
6. Presents results in a readable format

## Limitations

- Only works with Tenable's vulnerability database
- Depends on the current HTML structure of Tenable's website
- Rate-limited to avoid overwhelming the server

## License

MIT License - Feel free to modify and distribute as needed.

## Acknowledgments

- Tenable for providing the vulnerability database
- BeautifulSoup4 for HTML parsing capabilities
- Requests library for HTTP functionality