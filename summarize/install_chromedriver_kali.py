# Find Chrome version
CHROME_VERSION=$(google-chrome --version | grep -oP '\d+\.\d+\.\d+')
MAJOR_VERSION=$(echo $CHROME_VERSION | cut -d. -f1)

# Download matching driver
wget -O chromedriver.zip https://chromedriver.storage.googleapis.com/${CHROME_VERSION}/chromedriver_linux64.zip || \
wget -O chromedriver.zip https://chromedriver.storage.googleapis.com/${MAJOR_VERSION}.0.0.0/chromedriver_linux64.zip

unzip chromedriver.zip
chmod +x chromedriver
sudo mv chromedriver /usr/local/bin/
