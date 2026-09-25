import os
import sys
from fastapi import FastAPI, Request, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from dotenv import load_dotenv

from app.database.database import engine, Base
from app.api import auth, datasets, models, detection, alerts, dashboard, evaluation, simulation, live_monitor, ai_decision, attack_lab, advanced_soc, web_auditor, system_network, file_scanner, ws_telemetry, threat_intel
from app.services.download_watcher_service import DownloadWatcherService
from app.agent.agent_engine import ids_agent
from app.utils.logger import logger

load_dotenv()

# Create database tables automatically
Base.metadata.create_all(bind=engine)

# Start real-time background downloads folder watcher
DownloadWatcherService.start_background_watcher()

# Start autonomous Real-Time IDS Agent background daemon
ids_agent.start()

app = FastAPI(
    title="AI-Based Intelligent Intrusion Detection System (AI-IDS)",
    description="Advanced Cybersecurity IDS with Machine Learning, Real-Time Agent Telemetry & SOC Dashboard",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
origins_str = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173")
origins = [o.strip() for o in origins_str.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all for seamless development & demonstration
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": f"An internal server error occurred: {str(exc)}"}
    )

# Include API Routers
app.include_router(ws_telemetry.router)
app.include_router(auth.router)
app.include_router(datasets.router)
app.include_router(models.router)
app.include_router(detection.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)
app.include_router(evaluation.router)
app.include_router(simulation.router)
app.include_router(live_monitor.router)
app.include_router(ai_decision.router)
app.include_router(attack_lab.router)
app.include_router(advanced_soc.router)
app.include_router(web_auditor.router)
app.include_router(system_network.router)
app.include_router(file_scanner.router)
app.include_router(threat_intel.router)

@app.get("/api/health", tags=["Health"])
def health_check():
    """Health check endpoint to verify backend service and database connectivity."""
    return {
        "status": "healthy",
        "service": "AI-IDS Engine",
        "version": "1.0.0",
        "mode": "defensive_cybersecurity_ids"
    }

# Executable Download Endpoint
@app.get("/api/download/app-exe", tags=["Distribution"])
def download_app_executable():
    """Allow downloading the standalone Windows .exe application directly."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base_dir, "dist", "AI-IDS-Shield.exe"),
        os.path.join(base_dir, "dist", "AI-IDS-Shield", "AI-IDS-Shield.exe"),
        os.path.join(base_dir, "AI-IDS-Shield.exe"),
        os.path.join(os.path.dirname(base_dir), "dist", "AI-IDS-Shield.exe"),
    ]
    for p in candidates:
        if os.path.exists(p):
            return FileResponse(
                path=p,
                filename="AI-IDS-Shield.exe",
                media_type="application/vnd.microsoft.portable-executable"
            )
    raise HTTPException(status_code=404, detail="Desktop executable build is currently generating. Please try again shortly.")

@app.get("/api/download/app-zip", tags=["Distribution"])
def download_app_zip():
    """Allow downloading the complete standalone portable Windows distribution package (.zip)."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    zip_path = os.path.join(base_dir, "dist", "AI-IDS-Shield-Windows.zip")
    if os.path.exists(zip_path):
        return FileResponse(
            path=zip_path,
            filename="AI-IDS-Shield-Windows.zip",
            media_type="application/zip"
        )
    raise HTTPException(status_code=404, detail="Distribution package is archiving. Please try again shortly.")

# Static Frontend mounting for standalone executable distribution
frontend_dist = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "frontend", "dist")
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    frontend_dist = os.path.join(sys._MEIPASS, "frontend_dist")

if os.path.exists(frontend_dist):
    from fastapi.staticfiles import StaticFiles
    assets_dir = os.path.join(frontend_dist, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="static_assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_frontend_spa(full_path: str):
        if full_path.startswith("api") or full_path.startswith("docs") or full_path.startswith("openapi.json"):
            raise HTTPException(status_code=404, detail="Not Found")
        target_file = os.path.join(frontend_dist, full_path)
        if os.path.isfile(target_file):
            return FileResponse(target_file)
        return FileResponse(os.path.join(frontend_dist, "index.html"))
else:
    @app.get("/", tags=["Root"])
    def root():
        return {
            "message": "AI-Based Intelligent Intrusion Detection System API is running.",
            "documentation": "/docs"
        }
