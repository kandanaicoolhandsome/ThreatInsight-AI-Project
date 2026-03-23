import os
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
import models

# Config
SQLALCHEMY_DATABASE_URL = "sqlite:///./threat_insight.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = Session(bind=engine)

def seed():
    db = SessionLocal
    # 1. Create Sample CTI Data
    sample_reports = [
        {
            "title": "VoidStealer malware steals Chrome master key via debugger trick",
            "source": "BleepingComputer",
            "summary": "แฮกเกอร์ใช้เทคนิค Debugger เพื่อหลอกเอา Master Key จาก Chrome เพื่อเข้าถึงรหัสผ่านทั้งหมดของผู้ใช้ แนะนำให้ทำการ Patch เบราว์เซอร์ทันที",
            "hunt": "ตรวจสอบการทำงานของกระบวนการที่ไม่พ้นขีดจำกัดหน่วยความจำในโฟลเดอร์ AppData/Local/Google/Chrome/User Data/Default",
            "vulnerabilities": [{"cve": "N/A", "product": "Google Chrome", "severity": "CRITICAL"}]
        },
        {
            "title": "AstraZeneca Data Breach – LAPSUS$ Group Allegedly Claims Access to Internal Data",
            "source": "The Hacker News",
            "summary": "กลุ่ม LAPSUS$ อ้างว่าเข้าถึงข้อมูลภายในของ AstraZeneca สำเร็จ คาดว่าเกิดจากบัญชีพนักงานที่ถูกขโมย หรือการตั้งค่าผิดพลาดของระบบยืมจ่ายสิทธิ์เข้าถึงพนักงาน",
            "hunt": "ตรวจสอบ Log การ Login ที่ผิดปกติจากต่างประเทศ (Anomalous Login) และการดึงข้อมูลขนาดใหญ่ผิดปกติ (Mass Data Exfiltration)",
            "vulnerabilities": []
        }
    ]

    for r in sample_reports:
        # Check if exists
        existing = db.query(models.NewsReport).filter(models.NewsReport.title == r['title']).first()
        if not existing:
            report = models.NewsReport(
                title=r['title'],
                source=r['source'],
                content_raw=r['summary'],
                executive_summary=r['summary'],
                hunt_pack=r['hunt']
            )
            db.add(report)
            db.flush()
            
            for v in r['vulnerabilities']:
                db.add(models.Vulnerability(
                    report_id=report.id,
                    cve=v['cve'],
                    product=v['product'],
                    severity=v['severity']
                ))
            db.commit()
            print(f"Seeded: {r['title']}")

if __name__ == "__main__":
    seed()
