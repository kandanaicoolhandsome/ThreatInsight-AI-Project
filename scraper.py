import feedparser
import httpx
from bs4 import BeautifulSoup
import time
import json

# --- Target Intelligence Sources ---
FEEDS = [
    {"name": "Cyber Security News", "url": "https://cybersecuritynews.com/feed/"},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/rss.xml"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Security Online", "url": "https://securityonline.info/feed/"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"}
]

# CISA KEV JSON URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

async def fetch_feeds_and_process(db, process_func):
    """Fetch intelligence from global sources and CISA KEV."""
    
    # --- PHASE 1: CISA KEV (RECOVERY VERSION) ---
    print("📡 Connecting to CISA KEV Center...")
    # Using a professional User-Agent to avoid blocks
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    
    try:
        async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=15.0, verify=False) as client:
            r = await client.get(CISA_KEV_URL)
            if r.status_code == 200:
                data = r.json()
                # LIMIT: ONLY THE SINGLE LATEST VULNERABILITY (FOR SPEED & CLEANLINESS)
                for vuln in data['vulnerabilities'][:1]:
                    title = f"ALARM: CISA Added {vuln['cveID']} to KEV Catalog"
                    source = "CISA KEV"
                    sUrl = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                    pub_time = vuln.get('dateAdded', time.strftime("%Y-%m-%d"))
                    # Normalize date format
                    try:
                        pub_time = time.strftime("%d/%m/%Y 00:00", time.strptime(pub_time, "%Y-%m-%d"))
                    except:
                        pub_time = time.strftime("%d/%m/%Y 00:00")
                        
                    content = f"Vulnerability in {vuln['vendorProject']} {vuln['product']}. Description: {vuln['shortDescription']}. Required Action: {vuln['requiredAction']}"
                    await process_func(title, source, pub_time, content, sUrl)
                    print(f"✅ CISA KEV Synchronized: {vuln['cveID']}")
            else:
                print(f"⚠️ CISA Proxy Issue: HTTP {r.status_code}")
    except Exception as e:
        print(f"❌ CISA Connection Blocked: {e}")

    # --- PHASE 2: GLOBAL RSS FEEDS ---
    for feed_info in FEEDS:
        print(f"📡 Scanning Feed: {feed_info['name']}")
        try:
            feed = feedparser.parse(feed_info['url'])
            for entry in feed.entries[:1]:
                entry_title = entry.get('title', 'No Title')
                entry_link = entry.get('link', '#')
                pub_date = entry.get('published_parsed', entry.get('updated_parsed', time.localtime()))
                entry_time = time.strftime("%d/%m/%Y %H:%M", pub_date)
                
                clean_text = ""
                if 'content' in entry:
                    clean_text = BeautifulSoup(entry.content[0].value, "html.parser").get_text()[:4000]
                elif 'summary' in entry:
                    clean_text = BeautifulSoup(entry.summary, "html.parser").get_text()[:4000]
                elif 'description' in entry:
                    clean_text = BeautifulSoup(entry.description, "html.parser").get_text()[:4000]
                
                await process_func(entry_title, feed_info['name'], entry_time, clean_text, entry_link)
                
        except Exception as e:
            print(f"❌ Failed to fetch {feed_info['name']}: {e}")

from urllib.parse import urlparse

async def scrape_single_url(url: str):
    """Scrape and clean content from a single dedicated URL."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    try:
        async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=20.0, verify=False) as client:
            r = await client.get(url)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                
                # Try to get a clean title
                title = soup.title.string if soup.title else "News from External Link"
                
                # Extract Domain Name for better sourcing
                domain = urlparse(url).netloc.replace('www.', '')
                site_name = domain.split('.')[0].capitalize() # e.g. cybersecuritydive
                
                # Remove script and style elements
                for script in soup(["script", "style", "nav", "footer", "header"]):
                    script.decompose()
                
                # Get text and clean it
                clean_text = soup.get_text(separator=' ', strip=True)[:5000]
                
                return {
                    "title": title.strip(),
                    "content": clean_text,
                    "url": url,
                    "source": site_name,
                    "time": time.strftime("%d/%m/%Y %H:%M")
                }
            else:
                print(f"⚠️ External Scrape Status: {r.status_code}")
                return None
    except Exception as e:
        print(f"❌ External Scrape Error: {e}")
        return None
