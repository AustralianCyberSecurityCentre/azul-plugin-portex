# This scripts installs the portex binary into `/usr/bin`
# This makes it available to run and avoids some of the complexity with finding the binary at runtime.

set -e

# Remove previous install
rm -f PortexAnalyzer.jar
rm -f /usr/bin/portex

# Download version 5.0.7 of Portex (last updated October 2026)
wget https://github.com/struppigel/PortEx/releases/download/v5.0.7/PortexAnalyzer.jar
mv PortexAnalyzer.jar /usr/bin/portex
chmod +x /usr/bin/portex
echo "portex installed"