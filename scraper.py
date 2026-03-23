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

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

async def fetch_feeds_and_process(db, process_func):
    """Fetch intelligence from global sources and CISA KEV."""
    
    # --- PHASE 1: CISA KEV ---
    print("📡 Connecting to CISA KEV Center...")
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(CISA_KEV_URL)
            if r.status_code == 200:
                data = r.json()
                latest_vuln = data['vulnerabilities'][0]
                
                title = f"ALARM: CISA Added {latest_vuln['cveID']} to KEV Catalog"
                source = "CISA KEV"
                sUrl = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                pub_time = latest_vuln.get('dateAdded', time.strftime("%Y-%m-%d"))
                pub_time = time.strftime("%d/%m/%Y 00:00", time.strptime(pub_time, "%Y-%m-%d"))
                
                content = f"Vulnerability in {latest_vuln['vendorProject']} {latest_vuln['product']}. Action: {latest_vuln['requiredAction']}"
                
                # Pass Link to process
                await process_func(title, source, pub_time, content, sUrl)
    except Exception as e:
        print(f"❌ CISA Sync Failed: {e}")

    # --- PHASE 2: GLOBAL RSS FEEDS ---
    for feed_info in FEEDS:
        print(f"📡 Scanning Feed: {feed_info['name']}")
        try:
            feed = feedparser.parse(feed_info['url'])
            for entry in feed.entries[:1]:
                entry_title = entry.get('title', 'No Title')
                entry_link = entry.get('link', '#') # THE LINK!
                pub_date = entry.get('published_parsed', entry.get('updated_parsed', time.localtime()))
                entry_time = time.strftime("%d/%m/%Y %H:%M", pub_date)
                
                clean_text = ""
                if 'content' in entry:
                    clean_text = BeautifulSoup(entry.content[0].value, "html.parser").get_text()[:3000]
                elif 'summary' in entry:
                    clean_text = BeautifulSoup(entry.summary, "html.parser").get_text()[:3000]
                elif 'description' in entry:
                    clean_text = BeautifulSoup(entry.description, "html.parser").get_text()[:3000]
                
                # Pass Link to process
                await process_func(entry_title, feed_info['name'], entry_time, clean_text, entry_link)
                
        except Exception as e:
            print(f"❌ Failed to fetch {feed_info['name']}: {e}")
