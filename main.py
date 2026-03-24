import asyncio
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
    db = SessionLocal()
    try:
        print("🚀 STARTUP: Initializing Deep Intelligence Sync...")
        asyncio.create_task(sync_data_task(db))
    finally:
        db.close()
    
    # B. Set up recurring task (Every 30 mins)
    scheduler.add_job(auto_sync_job, 'interval', minutes=30)
    scheduler.start()
    print("🤖 AUTO-ENGINE: Scheduler is running (Sync every 30 mins)")

async def auto_sync_job():
    db = SessionLocal()
    try:
        print("🕒 SCHEDULED: Running Auto Intel Update...")
        await sync_data_task(db)
    finally:
        db.close()

# --- API ENDPOINTS ---

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/news")
async def get_latest_news(db: Session = Depends(get_db)):
    reports = db.query(models.NewsReport).order_by(models.NewsReport.id.desc()).all()
    result = []
    for r in reports:
        result.append({
            "id": r.id,
            "title": r.title,
            "source": r.source,
            "source_url": r.source_url,
            "published_time": r.published_time,
            "category": r.category,
            "executive_summary": r.executive_summary,
            "hunt_pack": r.hunt_pack,
            "vulnerabilities": [{"cve": v.cve, "product": v.product, "severity": v.severity, "kev": v.kev_status, "epss": v.epss_score} for v in r.vulnerabilities] if r.vulnerabilities else [],
            "indicators": [{"type": i.type, "value": i.value} for i in r.indicators] if r.indicators else [],
            "campaigns": [{"name": c.name, "summary": c.summary, "sector": c.target_sector, "country": c.target_country} for c in r.campaigns] if r.campaigns else []
        })
    return result

@app.post("/sync")
async def manual_sync_endpoint(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    background_tasks.add_task(sync_data_task, db)
    return {"message": "Manual Sync Started..."}

async def sync_data_task(db: Session):
    async def process_and_save(entry_title, entry_source, entry_time, clean_text, source_url):
        try:
            existing = db.query(models.NewsReport).filter(models.NewsReport.title == entry_title).first()
            if existing: return

            print(f"Analyzing: {entry_title}")
            cti_data = await processor.extract_cti_data(clean_text)
            if not cti_data: return

            report = models.NewsReport(
                title=entry_title, source=entry_source, source_url=source_url,
                category=cti_data.get('category', 'Info'),
                published_time=entry_time, executive_summary=cti_data.get('executive_summary', ''),
                hunt_pack=cti_data.get('hunt_pack', ''), content_raw=clean_text
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
                db.add(models.Indicator(report_id=report.id, type=i.get('type',''), value=i.get('value',''), confidence='MED'))

            db.commit()
            print(f"SUCCESS: {entry_title}")
        except Exception as e:
            print(f"FAILED Sync: {e}")
            db.rollback()

    await scraper.fetch_feeds_and_process(db, process_and_save)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
