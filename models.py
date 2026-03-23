from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean, Float
from sqlalchemy.orm import relationship
from database import Base
import datetime

class NewsReport(Base):
    __tablename__ = "news_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    source = Column(String)
    source_url = Column(String) # For direct link
    published_date = Column(DateTime, default=datetime.datetime.utcnow)
    published_time = Column(String) # For display
    content_raw = Column(Text)
    category = Column(String)
    executive_summary = Column(Text)
    hunt_pack = Column(Text)
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="report")
    indicators = relationship("Indicator", back_populates="report")
    campaigns = relationship("Campaign", secondary="report_campaign_link", back_populates="reports")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("news_reports.id"))
    cve = Column(String)
    product = Column(String)
    severity = Column(String)
    kev_status = Column(Boolean, default=False) # CISA KEV
    epss_score = Column(Float, default=0.0) # EPSS
    
    report = relationship("NewsReport", back_populates="vulnerabilities")

class Indicator(Base):
    __tablename__ = "indicators"
    
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("news_reports.id"))
    type = Column(String) # ip, domain, url, hash, email
    value = Column(String)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    confidence = Column(String) # High, Medium, Low
    
    report = relationship("NewsReport", back_populates="indicators")

class Campaign(Base):
    __tablename__ = "campaigns"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    target_sector = Column(String)
    target_country = Column(String)
    summary = Column(Text)
    
    reports = relationship("NewsReport", secondary="report_campaign_link", back_populates="campaigns")

class ReportCampaignLink(Base):
    __tablename__ = "report_campaign_link"
    report_id = Column(Integer, ForeignKey("news_reports.id"), primary_key=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), primary_key=True)
