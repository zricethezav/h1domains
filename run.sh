#!/bin/sh
python3 hackerone.py

echo "# h1domains\nhackerone \"in-scope\" domains\n\n\`python3 hackerone.py\`" > README.md
echo "## Domains with Bounties (Last Updated `date`)" >> README.md
echo "\`\`\`" >> README.md
echo "`cat domains_with_bounties.txt`" >> README.md
echo "\`\`\`" >> README.md
