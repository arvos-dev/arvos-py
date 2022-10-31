import anybadge
import csv
import sys
import os 

scores = {
    'CRITICAL': 0,
    'HIGH': 0,
    'MEDIUM': 0,
    'LOW': 0
}

vuln_scores = os.environ.get('VULNERABILITY_SCORES')

if not vuln_scores:
    try:
        with open('arvos-report.csv') as fp:
            reader = csv.DictReader(fp)
            for row in reader:
                score = row['Score']
                if score in scores:
                    scores[score] += 1
    except:
        print("File not found")
        sys.exit(1)
else:
    vuln_scores = vuln_scores.split()
    for i in range(2, len(vuln_scores), 2):
        scores[vuln_scores[i].strip(':')] = int(vuln_scores[i + 1].strip(','))

print(scores)
if scores['CRITICAL'] > 0:
    color = 'crimson'
elif scores['HIGH'] > 0:
    color = 'orangered'
elif scores['MEDIUM'] > 0:
    color = 'orange_2'
elif scores['LOW'] > 0:
    color = 'yellow'
else:
    color = 'green'

vuln_count = scores['CRITICAL'] + scores['HIGH'] + scores['MEDIUM'] + scores['LOW']
value = f"Vulnerabilites: {vuln_count}, CRITICAL: {scores['CRITICAL']}, HIGH: {scores['HIGH']}, MEDIUM: {scores['MEDIUM']}, LOW: {scores['LOW']}"

badge = anybadge.Badge('Arvos', value, default_color=color)
badge.write_badge('arvos-report.svg', overwrite=True)