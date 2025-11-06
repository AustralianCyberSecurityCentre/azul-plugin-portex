# This scripts installs the portex binary into `/usr/bin`
# This makes it available to run and avoids some of the complexity with finding the binary at runtime.

set -e

# Remove previous install
rm -f PortexAnalyzer.jar
rm -f /usr/bin/portex

# Download latest version of Portex (last updated June 2025)
wget https://github.com/struppigel/PortEx/raw/master/progs/PortexAnalyzer.jar
mv PortexAnalyzer.jar /usr/bin/portex
chmod +x /usr/bin/portex
echo "portex installed"