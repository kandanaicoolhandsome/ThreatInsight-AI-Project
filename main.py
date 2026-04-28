import asyncio
import json
from pydantic import BaseModel
from fastapi import FastAPI, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import models, scraper, processor
from database import SessionLocal, engine

# 1. Initialize DB
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Threat Insight - THE AUTO-CTI EDITION")

# 2. CORS Support
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. DB Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- THE AUTO ENGINE: APScheduler ---
scheduler = AsyncIOScheduler()

@app.on_event("startup")
async def start_scheduler():
    # A. Initial Sync on Startup
    try:
        print("🚀 STARTUP: Initializing Deep Intelligence Sync...")
        asyncio.create_task(sync_data_task())
    finally:
        pass
    
    # B. Set up recurring task (Every 30 mins)
    scheduler.add_job(auto_sync_job, 'interval', minutes=30)
    scheduler.start()
    print("🤖 AUTO-ENGINE: Scheduler is running (Sync every 30 mins)")

async def auto_sync_job():
    print("🕒 SCHEDULED: Running Auto Intel Update...")
    await sync_data_task()

# --- API ENDPOINTS ---

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/news")
async def get_latest_news(db: Session = Depends(get_db)):
    reports = db.query(models.NewsReport).order_by(models.NewsReport.id.desc()).all()
    print(f"📡 API /news: Sending {len(reports)} intel reports to frontend")
    result = []
    for r in reports:
        result.append({
            "id": r.id,
            "title": r.title,
            "source": r.source,
            "source_url": r.source_url,
            "published_time": r.published_time,
            "category": r.category,
            "executive_summary": json.loads(r.executive_summary) if r.executive_summary and r.executive_summary.startswith(('[', '{')) else r.executive_summary,
            "intelligence_context": json.loads(r.intelligence_context) if r.intelligence_context and r.intelligence_context.strip() else None,
            "vulnerabilities": [{"cve": v.cve, "product": v.product, "severity": v.severity, "kev": v.kev_status, "epss": v.epss_score} for v in r.vulnerabilities] if r.vulnerabilities else [],
            "indicators": [{"type": i.type, "value": i.value, "description": i.description, "confidence": i.confidence} for i in r.indicators] if r.indicators else [],
            "campaigns": [{"name": c.name, "summary": c.summary, "sector": c.target_sector, "country": c.target_country} for c in r.campaigns] if r.campaigns else []
        })
    return result

@app.delete("/news/{news_id}")
async def delete_news(news_id: int, db: Session = Depends(get_db)):
    report = db.query(models.NewsReport).filter(models.NewsReport.id == news_id).first()
    if report:
        # Also clean up linked vulnerabilities/indicators if not handled by cascades
        db.delete(report)
        db.commit()
        return {"message": "News deleted successfully"}
    return {"message": "News not found"}, 404

@app.post("/sync")
async def manual_sync_endpoint(background_tasks: BackgroundTasks):
    background_tasks.add_task(sync_data_task)
    return {"message": "Manual Sync Started..."}

class URLRequest(BaseModel):
    url: str

@app.post("/analyze-url")
async def analyze_custom_url(request: URLRequest):
    # Now we await directly to give real-time feedback to the user
    success = await process_custom_url(request.url)
    if success:
        return {"message": "Success! News analysis complete and added to feed."}
    else:
        return {"message": "Failed to analyze the URL. The content might be protected or too complex."}, 400

async def process_custom_url(url: str):
    db = SessionLocal()
    try:
        print(f"🔗 MANUAL SCRAPE: {url}")
        sciped_data = await scraper.scrape_single_url(url)
        if sciped_data:
            success = await core_process_and_save(
                db, 
                sciped_data['title'], 
                sciped_data['source'], 
                sciped_data['time'], 
                sciped_data['content'], 
                sciped_data['url']
            )
            return success
        return False
    finally:
        db.close()

async def core_process_and_save(db: Session, entry_title, entry_source, entry_time, clean_text, source_url):
    try:
        existing = db.query(models.NewsReport).filter(models.NewsReport.title == entry_title).first()
        if existing:
            print(f"⏩ SKIPPED (Already Sync'd): {entry_title}")
            return True # Consider it a success if it's already there

        print(f"🧠 ANALYZING: {entry_title}")
        cti_data = await processor.extract_cti_data(clean_text, title=entry_title)
        
        if not cti_data:
            print(f"❌ FAILED ANALYSIS: {entry_title}")
            return False

        report = models.NewsReport(
            title=entry_title, source=entry_source, source_url=source_url,
            category=cti_data.get('category', 'Info'),
            published_time=entry_time, 
            executive_summary=json.dumps(cti_data.get('executive_summary', [])),
            intelligence_context=json.dumps(cti_data.get('intelligence_context', {})),
            content_raw=clean_text
        )
        db.add(report)
        db.flush()

        for v in cti_data.get('vulnerabilities', []):
            enrich = await processor.enrich_vulnerability(v.get('cve', ''))
            db.add(models.Vulnerability(
                report_id=report.id, cve=v.get('cve',''), product=v.get('product',''), severity=v.get('severity',''),
                kev_status=enrich.get('kev_status', False), epss_score=enrich.get('epss_score', 0.12)
            ))

        for i in cti_data.get('indicators', []):
            db.add(models.Indicator(
                report_id=report.id, 
                type=i.get('type',''), 
                value=i.get('value',''), 
                description=i.get('description', ''),
                confidence=i.get('confidence','MED')
            ))

        db.commit()
        print(f"✅ SUCCESS: {entry_title}")
        return True
    except Exception as e:
        print(f"💥 FAILED Process: {e}")
        db.rollback()
        return False

async def sync_data_task():
    db = SessionLocal()
    async def process_adapter(entry_title, entry_source, entry_time, clean_text, source_url):
        nonlocal db
        await core_process_and_save(db, entry_title, entry_source, entry_time, clean_text, source_url)
        await asyncio.sleep(2) # Breath

    try:
        await scraper.fetch_feeds_and_process(db, process_adapter)
    finally:
        db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
