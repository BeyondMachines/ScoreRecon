import requests
from bs4 import BeautifulSoup
import time
import sys
import csv
from datetime import datetime
import re


def extract_cves_from_text(text):
    """Extract all CVE IDs from the given text using regex"""
    # Regular expression pattern for CVE IDs (CVE-YYYY-NNNNN+)
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    
    # Find all matches
    cves = re.findall(cve_pattern, text)
    
    # Return unique CVEs (preserve order)
    unique_cves = []
    seen = set()
    for cve in cves:
        if cve not in seen:
            unique_cves.append(cve)
            seen.add(cve)
    
    return unique_cves


def get_cvss_scores(cve_id):
    """Extract CVSS scores for a given CVE ID from Tenable website"""
    url = f"https://www.tenable.com/cve/{cve_id}"
    scores = {"cvss2": None, "cvss3": None, "cvss4": None}
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code != 200:
            print(f"Error accessing {url}: Status code {response.status_code}")
            return scores
        
        # Parse HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all CVSS version headings
        cvss_headings = soup.find_all('h5', class_='mt-1 mb-3')
        
        for heading in cvss_headings:
            # Skip if no anchor or not a CVSS heading
            anchor = heading.find('a')
            if not anchor or 'CVSS' not in anchor.text:
                continue
                
            heading_text = anchor.text.strip()
            
            # Look for the div after the heading
            next_div = heading.find_next('div')
            if not next_div:
                continue
            
            # Find the paragraph with "Base Score" in it
            base_score_p = next_div.find('p', string=lambda s: s and 'Base Score' in s)
            if not base_score_p:
                base_score_p = next_div.find('p')
                if not base_score_p or not base_score_p.find('strong') or 'Base Score' not in base_score_p.find('strong').text:
                    continue
            
            # Extract the score value from the span
            score_span = base_score_p.find('span')
            if not score_span:
                continue
                
            score = score_span.text.strip()
            
            # Assign to the appropriate version
            if 'CVSS v2' in heading_text:
                scores['cvss2'] = float(score)
            elif 'CVSS v3' in heading_text:
                scores['cvss3'] = float(score)
            elif 'CVSS v4' in heading_text:
                scores['cvss4'] = float(score)
        
        return scores
        
    except Exception as e:
        print(f"Error processing {cve_id}: {e}")
        return scores


def get_cvss3_score(result):
    # Extract CVSS3 score (index 2 in the tuple)
    cvss3 = result[2]
    # Handle None values by returning -1 (to sort them to the end)
    return cvss3 if cvss3 is not None else -1


def main():
    # Check if input is provided via command line arguments
    if len(sys.argv) > 1:
        # If the first argument is a CVE list with commas
        if "CVE-" in sys.argv[1] and "," in sys.argv[1]:
            cve_list = [cve.strip() for cve in sys.argv[1].split(',')]
        else:
            # Combine all command line arguments into one text
            text = ' '.join(sys.argv[1:])
            cve_list = extract_cves_from_text(text)
    else:
        # If no command line arguments, read from stdin until EOF
        print("Enter or paste text containing CVE IDs (press Ctrl+D or Ctrl+Z on a new line when done):")
        text = sys.stdin.read()
        cve_list = extract_cves_from_text(text)
    
    if not cve_list:
        print("No CVEs found in the provided text.")
        return
    
    total_cves = len(cve_list)
    print(f"\nScoreRecon found {total_cves} unique CVE IDs:")
    for i, cve in enumerate(cve_list):
        print(f"{i+1}. {cve}")
    
    print(f"\nStarting vulnerability intelligence gathering for {total_cves} CVEs...")
    
    results = []
    
    # Process each CVE in the list
    for i, cve_id in enumerate(cve_list):
        print(f"\nInvestigating {cve_id} ({i+1}/{total_cves})...")
        scores = get_cvss_scores(cve_id)
        
        # Check if any scores were found
        if any(scores.values()):
            print(f"Found scores for {cve_id}:")
            if scores['cvss2']:
                print(f"  CVSS v2 Base Score: {scores['cvss2']}")
            if scores['cvss3']:
                print(f"  CVSS v3 Base Score: {scores['cvss3']}")
            if scores['cvss4']:
                print(f"  CVSS v4 Base Score: {scores['cvss4']}")
            
            results.append((cve_id, scores['cvss2'], scores['cvss3'], scores['cvss4']))
        else:
            print(f"No CVSS scores found for {cve_id}")
            results.append((cve_id, None, None, None))
        
        # Be respectful to the server with a delay between requests
        if i < total_cves - 1:
            time.sleep(1.5)
    
    # Print summary of results
    print("\n--- SUMMARY ---")
    print(f"{'CVE ID':<15} {'CVSS v2':<10} {'CVSS v3':<10} {'CVSS v4':<10}")
    print("-" * 45)
    
    sorted_results = sorted(results, key=get_cvss3_score, reverse=True)

    # Print summary of results (now sorted)
    print("\n--- SUMMARY (sorted by CVSS v3 score, descending) ---")

    for cve, score2, score3, score4 in sorted_results:
        print(f"{cve:<15} {score2 if score2 else 'N/A':<10} {score3 if score3 else 'N/A':<10} {score4 if score4 else 'N/A':<10}")
    
    # Count how many scores of each type were found
    count_v2 = sum(1 for _, s2, _, _ in results if s2)
    count_v3 = sum(1 for _, _, s3, _ in results if s3)
    count_v4 = sum(1 for _, _, _, s4 in results if s4)
    
    print(f"\nFound {count_v2} CVSS v2 scores, {count_v3} CVSS v3 scores, and {count_v4} CVSS v4 scores")
    print(f"Total CVEs with at least one score: {sum(1 for r in results if any(r[1:]))}/{total_cves}")


if __name__ == "__main__":
    main()
