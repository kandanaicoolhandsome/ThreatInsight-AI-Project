import os
import json
import httpx
from dotenv import load_dotenv

load_dotenv()

# OpenAI Configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
OPENAI_URL = "https://api.openai.com/v1/chat/completions"

# Google Search Configuration
GOOGLE_API_KEY = os.getenv("GOOGLE_SEARCH_API_KEY")
GOOGLE_CSE_ID = os.getenv("GOOGLE_CSE_ID")

SYSTEM_PROMPT = """คุณคือ Senior Cyber Threat Intelligence Analyst (Expert Level)
ภารกิจ: วิเคราะห์เนื้อหาข่าวและสกัดข้อมูล CTI ที่แม่นยำ พร้อมอธิบายบริบททางเทคนิคให้เข้าใจง่าย

[STRICT OUTPUT RULES]
1. NO SEARCH NOISE: ห้ามเขียนข้อความอธิบายปัญหาทางเทคนิคหรือการค้นหาล้มเหลวเด็ดขาด
2. NATURAL THAI DESCRIPTIONS: สำหรับ "description" ให้ใช้ภาษาไทยที่มนุษย์ใช้จริง (Natural Language) หลีกเลี่ยงการแปลตรงตัวจากภาษาอังกฤษที่ฟังดูติดขัด
   - ตัวอย่างที่ควรใช้: "ไฟล์ภายในเครื่อง" (แทนที่จะใช้ ไฟล์ระบบท้องถิ่น), "ช่องโหว่ในการยกระดับสิทธิ์", "การติดตั้งมัลแวร์เพื่อความคงอยู่"
3. ZERO HALLUCINATION: ห้ามเดาข้อมูล IOC เด็ดขาด ถ้าไม่มีในข่าวให้ปล่อยว่าง

[IOC SPECIFICATIONS]
- Network: IP, Domain, URL, User Agent, Email
- Files: Hashes (MD5, SHA-1, SHA-256), Names, Path
- Host: Registry Keys, Service Names, Mutex
- Tools & TTPs: Tools (Mimikatz, etc.), Techniques (PowerShell, Persistence)

[JSON STRUCTURE]
{
  "category": "Vulnerability" | "Malware" | "Attack" | "Info",
  "executive_summary": ["หัวข้อสรุป 1", "หัวข้อสรุป 2"...],
  "intelligence_context": {
    "attacker_group": "ชื่อกลุ่ม (English) หรือ null",
    "historical_narrative": ["บริบทประวัติศาสตร์ 1", "บริบทประวัติศาสตร์ 2"...]
  },
  "vulnerabilities": [{"cve": "รหัสจริง", "product": "...", "severity": "..."}],
  "indicators": [{"type": "...", "value": "...", "description": "อธิบายสั้นๆ ภาษาไทยที่เป็นธรรมชาติ", "confidence": "..."}],
  "campaign": { "name": "...", "target_sector": "...", "target_country": "ประเทศ (ภาษาไทย)", "summary": "..." }
}
"""
async def search_threat_intel(query: str):
    """ฟังก์ชันสำหรับไป Search หาประวัติ Hacker หรือ Link ข่าวที่เกี่ยวข้อง"""
    if not GOOGLE_API_KEY or not GOOGLE_CSE_ID or "YOUR_CUSTOM_SEARCH_ENGINE_ID" in GOOGLE_CSE_ID:
        return "No search credentials available."
    
    search_url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": GOOGLE_API_KEY,
        "cx": GOOGLE_CSE_ID,
        "q": query,
        "num": 3 # à¸”à¸¶à¸‡à¸¡à¸²à¸ªà¸±à¸� 3 à¸¥à¸´à¸‡à¸�à¹Œà¸—à¸µà¹ˆà¹€à¸�à¸µà¹ˆà¸¢à¸§à¸‚à¹‰à¸­à¸‡à¸—à¸µà¹ˆà¸ªà¸¸à¸”
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(search_url, params=params)
            if response.status_code == 200:
                data = response.json()
                results = []
                for item in data.get("items", []):
                    results.append(f"Title: {item.get('title')}\nSnippet: {item.get('snippet')}\nLink: {item.get('link')}")
                return "\n---\n".join(results)
    except Exception as e:
        print(f"â�Œ Search API Error: {e}")
    return "Search failed or returned no results."

async def extract_cti_data(content: str, title: str = ""):
    """Balanced Extract: Descriptive by default, Precise for lists."""
    if not OPENAI_API_KEY: return None

    # Step 1: Search for context focusing on Threat Actor Attribution
    search_results = ""
    if title:
        targeted_query = f"'{title}' threat actor attribution hacker group history"
        search_results = await search_threat_intel(targeted_query)
    elif content:
        targeted_query = f"{content[:100]} threat attribution"
        search_results = await search_threat_intel(targeted_query)
    
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    
    user_prompt = f"[NEWS CONTENT TO ANALYSE]:\n{content}\n\n"
    if search_results:
        user_prompt += f"[GROUNDING CONTEXT: WEB SEARCH RESULTS]:\n{search_results}\n\n"
        user_prompt += "INSTRUCTION: ใช้ข้อมูลจาก [GROUNDING CONTEXT] ค้นหา Threat Actor และประวัติ หากไม่เห็นกลุ่มชัดเจน ให้ใช้ความรู้ของคุณวิเคราะห์ TTPs เพื่อทำ Attribution แทน"
    else:
        user_prompt += "INSTRUCTION: วิเคราะห์จากเนื้อหาต้นฉบับและความรู้ของคุณเพื่อระบุกลุ่มผู้โจมตีหรือบริบทเชิงความเสี่ยงของผลิตภัณฑ์ที่เกี่ยวข้อง"

    payload = {
        "model": "gpt-5-mini",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        "response_format": {"type": "json_object"}
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(OPENAI_URL, headers=headers, json=payload, timeout=60.0)
            if response.status_code == 200:
                return json.loads(response.json()['choices'][0]['message']['content'])
            elif response.status_code == 429:
                print(f"🛑 Rate Limit Exceeded (429) - OpenAI API is busy. Try again later.")
            else:
                print(f"⚠️ OpenAI API Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"âŒ AI Analysis Exception: {e}")
    return None

async def enrich_vulnerability(cve_id):
    return {"kev_status": True, "epss_score": 0.3}

async def fetch_historical_context(subject_name: str):
    """
    Search for historical cyber attacks and technical details related to a subject.
    Now uses the implemented search_threat_intel function.
    """
    return await search_threat_intel(subject_name)
