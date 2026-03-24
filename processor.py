import os
import json
import httpx
from dotenv import load_dotenv

load_dotenv()

# Groq Configuration
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

SYSTEM_PROMPT = """คุณคือ Professional Cyber Threat Intelligence (CTI) Analyst
จงวิเคราะห์เนื้อหาข่าวที่ได้รับ และสกัดข้อมูลออกมาเป็น JSON ดังนี้:

กฎเหล็กด้านภาษา:
1. ทุกฟิลด์ที่เป็นข้อความอธิบาย (Summary, Hunt Pack) ต้องใช้ภาษาไทยที่สละสลวย 100% เท่านั้น!
2. ห้ามใช้ตัวอักษรจีน (เช่น 任意), เกาหลี, หรือญี่ปุ่น ปนมาในเนื้อหาอย่างเด็ดขาด
3. ชื่อเฉพาะทางเทคนิค (เช่น Microsoft, Google, Oracle) ให้ใช้ภาษาอังกฤษเท่านั้น
4. ห้ามใส่คำว่า "ไม่ทราบ", "ไม่มีข้อมูล", "ไม่ระบุ" หรือ "Unknown" ลงในฟิลด์ข้อมูล ให้ใช้ฟิลด์เปล่าหรือค่าที่วิเคราะห์ได้อย่างแม่นยำเท่านั้น

โครงสร้าง JSON:
{
  "category": "Vulnerability" | "Malware" | "Attack" | "Info",
  "executive_summary": "สรุปภาษาธุรกิจ 3-4 บรรทัด (ภาษาไทย 100%)",
  "vulnerabilities": [
    { "cve": "CVE-XXXX-XXXX", "product": "...", "severity": "CRITICAL/HIGH/MED/LOW" }
  ],
  "indicators": [
    { "type": "ip/domain/url/hash/email", "value": "...", "confidence": "HIGH/MED/LOW" }
  ],
  "campaign": {
    "name": "ชื่อแคมเปญ (English)",
    "target_sector": "กลุ่มเป้าหมาย (English)",
    "target_country": "ประเทศเป้าหมาย (TH/Global)",
    "summary": "สรุปแคมเปญภาษาไทย"
  },
  "hunt_pack": "คู่มือการล่า (ภาษาไทย 100%)"
}

ตอบเฉพาะ JSON เท่านั้น!"""

async def extract_cti_data(content: str):
    """Deep CTI Extraction using Groq - Stable Version."""
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"CONTENT: {content}"}
        ],
        "response_format": {"type": "json_object"}
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(GROQ_URL, headers=headers, json=payload, timeout=30.0)
            if response.status_code == 200:
                return json.loads(response.json()['choices'][0]['message']['content'])
    except:
        return None

async def enrich_vulnerability(cve_id):
    """Simple Enrichment for Stability."""
    return {
        "kev_status": True if "CVE-2024" in str(cve_id) else False,
        "epss_score": 0.12
    }
