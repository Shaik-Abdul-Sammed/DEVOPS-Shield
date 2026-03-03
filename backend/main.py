"""
DevOps Fraud Shield Backend - Enhanced Security & Performance
Monitoring
======================================================================

A comprehensive FastAPI application for CI/CD security monitoring
and fraud detection with advanced security features, performance
monitoring, and blockchain integration.
"""

import os
import sys
import asyncio
import signal
import time
import logging
from pathlib import Path
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Dict, Any, cast

# Third-party imports
from dotenv import load_dotenv  # type: ignore
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect  # type: ignore
from fastapi.middleware.cors import CORSMiddleware  # type: ignore
from fastapi.middleware.trustedhost import TrustedHostMiddleware  # type: ignore
from fastapi.middleware.gzip import GZipMiddleware  # type: ignore
from fastapi.responses import JSONResponse, FileResponse  # type: ignore
from fastapi.staticfiles import StaticFiles  # type: ignore
import uvicorn  # type: ignore
import uuid
from typing import List

# Try to import performance monitoring modules
try:
    import psutil  # type: ignore
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

try:
    from prometheus_client import (  # type: ignore
        Counter,
        Histogram,
        Gauge,
        generate_latest,
        CONTENT_TYPE_LATEST
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    Counter = Histogram = Gauge = None
    generate_latest = CONTENT_TYPE_LATEST = None

# Security
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler  # type: ignore
    from slowapi.util import get_remote_address  # type: ignore
    from slowapi.errors import RateLimitExceeded  # type: ignore
    SLOWAPI_AVAILABLE = True
except ImportError:
    SLOWAPI_AVAILABLE = False
    Limiter = _rate_limit_exceeded_handler = None
    get_remote_address = RateLimitExceeded = None

# Application imports
try:
    from src.utils.logger import get_logger  # type: ignore
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False

    def get_logger(name):
        return logging.getLogger(name)


try:
    from src.utils.config import Config  # type: ignore
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

    class Config:
        def __init__(self):
            pass


try:
    from src.utils.metrics import MetricsCollector  # type: ignore
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

    class MetricsCollector:

        def __init__(self):
            pass

        async def start_monitoring(self):
            pass

        async def stop_monitoring(self):
            pass


try:
    from src.utils.database_pool import get_database_pool, DatabaseConfig  # type: ignore
    DATABASE_POOL_AVAILABLE = True
except ImportError:
    DATABASE_POOL_AVAILABLE = False

    def get_database_pool(config=None):
        return None

    class DatabaseConfig:

        def __init__(self, **kwargs):
            pass

try:
    from src.security.audit_logger import security_audit_logger  # type: ignore
    AUDIT_LOGGER_AVAILABLE = True
except ImportError:
    AUDIT_LOGGER_AVAILABLE = False

    class security_audit_logger:
        @staticmethod
        def log_security_event(event_type, details):
            pass

        @staticmethod
        def log_rate_limit_violation(ip, path):
            pass

        @staticmethod
        def log_security_audit_access(ip):
            pass

        @staticmethod
        async def get_recent_violations(limit=10):
            return []

        @staticmethod
        async def get_blocked_ips():
            return []

try:
    from src.security.backup_recovery import backup_manager  # type: ignore
    BACKUP_MANAGER_AVAILABLE = True
except ImportError:
    BACKUP_MANAGER_AVAILABLE = False

    class backup_manager:
        @staticmethod
        async def initialize():
            pass

        @staticmethod
        async def cleanup():
            pass

try:
    from src.security.secrets_manager import secret_vault  # type: ignore
    SECRETS_MANAGER_AVAILABLE = True
except ImportError:
    SECRETS_MANAGER_AVAILABLE = False

    class secret_vault:
        @staticmethod
        async def initialize():
            pass

# Initialize configuration and logging
load_dotenv()
logger = get_logger(__name__)
config = Config()

# Performance metrics (only if prometheus is available)
if PROMETHEUS_AVAILABLE:
    REQUEST_COUNT = Counter(  # type: ignore
        'http_requests_total',
        'Total HTTP requests',
        ['method', 'endpoint', 'status']
    )
    REQUEST_DURATION = Histogram(  # type: ignore
        'http_request_duration_seconds',
        'HTTP request duration'
    )
    ACTIVE_CONNECTIONS = Gauge(  # type: ignore
        'active_connections',
        'Active connections'
    )
    SYSTEM_MEMORY = Gauge(  # type: ignore
        'system_memory_usage_bytes',
        'System memory usage'
    )
    SYSTEM_CPU = Gauge(  # type: ignore
        'system_cpu_usage_percent',
        'System CPU usage'
    )
else:
    REQUEST_COUNT = None
    REQUEST_DURATION = None
    ACTIVE_CONNECTIONS = None
    SYSTEM_MEMORY = None
    SYSTEM_CPU = None

# Rate limiting (only if slowapi is available)
if SLOWAPI_AVAILABLE:
    limiter = Limiter(key_func=get_remote_address)  # type: ignore
else:
    limiter = None

# WebSocket Connection Manager


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            f"WebSocket connected. Total connections: "
            f"{len(self.active_connections)}"
        )

    async def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(
            f"WebSocket disconnected. Total connections: "
            f"{len(self.active_connections)}"
        )

    async def broadcast(self, message: dict):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            await self.disconnect(conn)


websocket_manager = ConnectionManager()

# Global application state
application_state = {
    "startup_time": datetime.now(timezone.utc),
    "request_count": 0,
    "error_count": 0,
    "last_health_check": None,
    "performance_metrics": {},
    "websocket_connections": 0
}

# Ensure proper Python path
_current_dir = Path(__file__).resolve().parent
_src_dir = _current_dir / "src"
for _candidate in (_current_dir, _src_dir):
    _candidate_str = str(_candidate)
    if _candidate_str not in sys.path:
        sys.path.insert(0, _candidate_str)

# Security middleware
try:
    from src.security.https_config import (  # type: ignore
        SecurityHeadersMiddleware
    )
    # Note: request_validator and ip_whitelist modules not available
    # Using conditional imports to avoid errors
    RequestValidationMiddleware = None
    IPWhitelistMiddleware = None
    security_modules_loaded = True
    logger.info("Security modules loaded successfully")  # type: ignore
except Exception as err:
    logger.error(f"Security modules failed to load: {err}")  # type: ignore
    security_modules_loaded = False
    SecurityHeadersMiddleware = None
    RequestValidationMiddleware = None
    IPWhitelistMiddleware = None

# Performance monitoring middleware
try:
    from src.middleware.performance_monitor import (  # type: ignore
        PerformanceMonitorMiddleware,
        CacheMiddleware,
        get_performance_metrics
    )
    from src.middleware.performance_monitor import (  # type: ignore
        reset_performance_metrics as reset_metrics
    )
    performance_modules_loaded = True
    logger.info("Performance monitoring modules loaded successfully")  # type: ignore
except Exception as err:
    logger.error(f"Performance monitoring modules failed to load: {err}")  # type: ignore
    performance_modules_loaded = False
    PerformanceMonitorMiddleware = None
    CacheMiddleware = None
    get_performance_metrics = None
    reset_metrics = None

# Initialize metrics collector (only if available)
if METRICS_AVAILABLE:
    metrics_collector = MetricsCollector()  # type: ignore
else:
    metrics_collector = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("Starting DevOps Fraud Shield Backend...")

    # Startup tasks
    try:
        # Initialize security components
        if security_modules_loaded:
            try:
                await secret_vault.initialize()
                await backup_manager.initialize()
                logger.info("Security components initialized")
            except Exception as err:
                msg = "Security components initialization failed"
                logger.warning(f"{msg} (non-critical): {err}")
        # Initialize performance monitoring
        if performance_modules_loaded and metrics_collector:
            try:
                await metrics_collector.start_monitoring()
                logger.info("Performance monitoring started")
            except Exception as err:
                msg = "Performance monitoring startup failed"
                logger.warning(f"{msg} (non-critical): {err}")
            # Initialize database pool
            if DATABASE_POOL_AVAILABLE:
                try:
                    db_config = DatabaseConfig(
                        host=os.getenv("DB_HOST", "localhost"),
                        port=int(os.getenv("DB_PORT", 5432)),
                        database=os.getenv(
                            "DB_NAME", "devops_shield"
                        ),
                        username=os.getenv("DB_USER", "postgres"),
                        password=os.getenv("DB_PASSWORD", ""),
                        min_connections=int(
                            os.getenv("DB_MIN_CONNECTIONS", 5)
                        ),
                        max_connections=int(
                            os.getenv("DB_MAX_CONNECTIONS", 20)
                        ),
                        enable_query_cache=(
                            os.getenv("DB_QUERY_CACHE", "true").lower()
                            == "true"
                        ),
                        query_cache_size=int(
                            os.getenv("DB_QUERY_CACHE_SIZE", 1000)
                        )
                    )
                    db_pool_init = get_database_pool(db_config)
                    if db_pool_init and asyncio.iscoroutine(db_pool_init):
                        await db_pool_init
                    elif db_pool_init and hasattr(db_pool_init, '__await__'):
                        await db_pool_init  # type: ignore
                    logger.info("Database pool initialized")
                except Exception as err:
                    msg = "Database pool initialization failed"
                    logger.warning(f"{msg} (non-critical): {err}")

        # Database health check (non-blocking)
        try:
            await check_database_health()
        except Exception as err:
            logger.warning(
                f"Database health check failed (non-critical): {err}"
            )

        # Blockchain connectivity check (non-blocking)
        try:
            await check_blockchain_connectivity()
        except Exception as err:
            logger.warning(
                f"Blockchain connectivity check failed (non-critical): {err}"
            )

        application_state["startup_time"] = datetime.now(timezone.utc)
        logger.info("Application startup completed successfully")

    except Exception as err:
        logger.error(f"Startup failed: {err}")
        raise

    yield

    # Shutdown tasks
    logger.info("Shutting down DevOps Fraud Shield Backend...")

    try:
        # Cleanup resources
        if performance_modules_loaded and metrics_collector:
            await metrics_collector.stop_monitoring()

        if security_modules_loaded and BACKUP_MANAGER_AVAILABLE:
            await backup_manager.cleanup()

        logger.info("Application shutdown completed")

    except Exception as err:
        logger.error(f"Shutdown error: {err}")

# Create FastAPI application
app = FastAPI(
    title="DevOps Fraud Shield API",
    version="2.0.0",
    description="Advanced CI/CD security monitoring and fraud "
    "detection platform",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
    contact={
        "name": "DevOps Security Team",
        "email": "security@devops-shield.com",
        "url": "https://devops-shield.com"
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT"
    }
)

# Add GZip compression middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)
logger.info("GZip compression middleware added")  # type: ignore

# Custom rate limit exceeded handler (only if slowapi is available)
if SLOWAPI_AVAILABLE and RateLimitExceeded:
    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_exceeded_handler(
            request: Request,
            exc: RateLimitExceeded
    ):
        """Custom rate limit exceeded handler with security logging"""
        client_ip = (
            get_remote_address(request)
            if get_remote_address
            else request.client.host
        )
        if AUDIT_LOGGER_AVAILABLE:
            security_audit_logger.log_rate_limit_violation(
                client_ip,
                request.url.path
            )

        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "message": "Too many requests, please try again later",
                "retry_after": (
                    exc.detail.retry_after
                    if exc and hasattr(exc, 'detail') and exc.detail
                    else 60
                )
            }
        )

# Security middleware (only if rate limiting is available)
if limiter:
    app.state.limiter = limiter

# Trusted host middleware
default_allowed_hosts = (
    "localhost,127.0.0.1,testserver,*.railway.app,"
    "*.onrender.com,*.devops-shield.com"
)
allowed_hosts = [
    host.strip()
    for host in os.getenv("ALLOWED_HOSTS", default_allowed_hosts).split(",")
    if host.strip()
]
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=allowed_hosts
)

# Security headers middleware
if security_modules_loaded and SecurityHeadersMiddleware:
    try:
        app.add_middleware(SecurityHeadersMiddleware)
        logger.info("Security headers middleware added")
    except Exception as err:
        logger.error(f"Failed to add security headers middleware: {err}")

# Request validation middleware
if security_modules_loaded and RequestValidationMiddleware:
    try:
        app.add_middleware(RequestValidationMiddleware)
        logger.info("Request validation middleware added")
    except Exception as err:
        logger.error(f"Failed to add request validation middleware: {err}")

# IP whitelist middleware (if enabled)
ip_whitelist_enabled = os.getenv("IP_WHITELIST_ENABLED", "false").lower()
if (security_modules_loaded and
        IPWhitelistMiddleware and
        ip_whitelist_enabled == "true"):
    try:
        app.add_middleware(IPWhitelistMiddleware)
        logger.info("IP whitelist middleware added")
    except Exception as err:
        logger.error(f"Failed to add IP whitelist middleware: {err}")

# Performance monitoring middleware
if performance_modules_loaded and PerformanceMonitorMiddleware:
    try:
        app.add_middleware(
            PerformanceMonitorMiddleware,
            enable_system_monitoring=True,
            system_monitoring_interval=30,
            enable_gc_monitoring=True,
            gc_threshold=1000
        )
        logger.info("Performance monitoring middleware added")
    except Exception as err:
        logger.error(
            f"Failed to add performance monitoring middleware: {err}"
        )

# Cache middleware
if performance_modules_loaded and CacheMiddleware:
    try:
        app.add_middleware(
            CacheMiddleware,
            cache_ttl=int(os.getenv("CACHE_TTL", 300)),
            max_cache_size=int(os.getenv("CACHE_MAX_SIZE", 1000)),
            cacheable_methods=["GET"],
            cacheable_status_codes=[200, 304]
        )
        logger.info("Cache middleware added")
    except Exception as err:
        logger.error(f"Failed to add cache middleware: {err}")

# CORS middleware (restricted)
default_origins = (
    "http://localhost:3000,http://localhost:5173,"
    "https://devops-shield.com,https://*.railway.app"
)
cors_origins_env = os.getenv("CORS_ORIGINS", default_origins)
allowed_origins = [
    origin.strip()
    for origin in cors_origins_env.split(",")
    if origin.strip()
]

# Handle wildcard patterns for Railway and other dynamic domains
if any("*" in origin for origin in allowed_origins):
    # If wildcards are present, use allow_origin_regex
    origin_patterns = []
    for origin in allowed_origins:
        if "*" in origin:
            # Convert wildcard pattern to regex
            pattern = origin.replace(".", r"\.").replace("*", ".*")
            origin_patterns.append(pattern)

    # Combine all patterns
    allow_origin_regex = (
        "|".join(f"({p})" for p in origin_patterns)
        if origin_patterns
        else None
    )

    app.add_middleware(
        CORSMiddleware,
        # Non-wildcard origins
        allow_origins=[o for o in allowed_origins if "*" not in o],
        allow_origin_regex=allow_origin_regex,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
        expose_headers=["X-Total-Count", "X-Rate-Limit-Remaining"],
        max_age=3600
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
        expose_headers=["X-Total-Count", "X-Rate-Limit-Remaining"],
        max_age=3600
    )


# API Routers
def include_router_safely(
        router_path: str,
        prefix: str,
        tags: list,
        router_name: str
):
    """Safely include a router with error handling"""
    try:
        # Handle both _controller.py and _routes.py naming conventions
        if '_controller' in router_path:
            module_path = f"src.api.{router_path}"
        elif '_routes' in router_path:
            module_path = f"src.api.{router_path}"
        else:
            # Default fallback
            module_path = f"src.api.{router_path}"

        module = __import__(module_path, fromlist=['router'])  # type: ignore
        router = getattr(module, 'router')

        app.include_router(router, prefix=prefix, tags=tags)
        logger.info(f"{router_name} router loaded successfully")
        return True
    except Exception as err:
        logger.error(f"{router_name} router error: {err}")
        logger.warning(f"Continuing without {router_name} router")
        return False


# Include all routers
routers_config = [
    ("auth_routes", "/api/auth", ["authentication"], "Authentication"),
    ("simulate_routes", "/api/simulate", ["simulation"], "Simulation"),
    ("fraud_controller", "/api/fraud", ["fraud"], "Fraud Detection"),
    ("alerts_controller", "/api/alerts", ["alerts"], "Alert Management"),
    (
        "pipelines_controller",
        "/api/pipelines",
        ["pipelines"],
        "Pipeline Monitoring"
    ),
    ("data_controller", "/api", ["data"], "Data Management"),
    ("zero_trust_controller", "/api", ["zero-trust"], "Zero Trust"),
    ("blockchain_controller", "/api/blockchain", ["blockchain"], "Blockchain"),
    ("webhook_handler", "/api/webhooks", ["webhooks"], "Webhook Handler"),
    ("github_integration", "", ["github"], "GitHub Integration"),
]

for router_path, prefix, tags, router_name in routers_config:
    include_router_safely(router_path, prefix, tags, router_name)

# Service status endpoint


@app.get("/api/status/services")
async def services_status():
    """Get status of all services and features"""
    return {
        "services": {
            "database": "healthy" if DATABASE_POOL_AVAILABLE else "unavailable",
            "blockchain": "enabled" if os.getenv("BLOCKCHAIN_ENABLED", "false").lower() == "true" else "disabled",
            "metrics": "healthy" if PROMETHEUS_AVAILABLE else "unavailable",
            "rate_limiting": "healthy" if SLOWAPI_AVAILABLE else "unavailable",
            "performance_monitoring": "healthy" if performance_modules_loaded else "unavailable",
            "websocket": "healthy",
            "security_modules": "healthy" if security_modules_loaded else "unavailable"
        },
        "connections": {
            "websocket": len(websocket_manager.active_connections),
            "active_requests": application_state["request_count"]
        },
        "degraded_mode": not all([DATABASE_POOL_AVAILABLE, performance_modules_loaded]),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# Enhanced health check
if limiter:
    @app.get("/health")
    @limiter.limit("100/minute")
    async def health_check(request: Request) -> Dict[str, Any]:
        """
        Comprehensive health check endpoint with detailed system status
        """
        start_time = time.time()

        try:
            health_status: Dict[str, Any] = {
                "status": "healthy",
                "service": "DevOps Shield Backend",
                "version": "2.0.0",
                "environment": os.getenv("ENVIRONMENT", "development"),
                "uptime_seconds": (
                    datetime.now(timezone.utc) -
                    cast(datetime, application_state["startup_time"])
                ).total_seconds(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "features": {
                    "security_monitoring": True,
                    "fraud_detection": True,
                    "blockchain_auditing": (
                        os.getenv("BLOCKCHAIN_ENABLED", "false").lower()
                        == "true"
                    ),
                    "real_time_alerts": True,
                    "attack_simulation": True,
                    "zero_trust_architecture": True,
                    "websocket_support": True,
                    "compression": True
                },
                "connections": {
                    "websocket": len(websocket_manager.active_connections),
                    "total_requests": application_state["request_count"],
                    "error_count": application_state["error_count"]
                },
                "client_info": {
                    "ip": (
                        request.client.host
                        if request.client
                        else "unknown"
                    ),
                    "user_agent": request.headers.get("user-agent", "Unknown"),
                    "request_id": getattr(request.state, 'request_id', 'N/A')
                }
            }

            # Add system metrics if available
            if PSUTIL_AVAILABLE and psutil:
                health_status["system"] = {
                    "memory_usage_percent": psutil.virtual_memory().percent,
                    "cpu_usage_percent": psutil.cpu_percent(interval=0.1),
                    "disk_usage_percent": (
                        psutil.disk_usage('/').used /
                        psutil.disk_usage('/').total * 100
                    )
                }

            # Add performance metrics if available
            if PROMETHEUS_AVAILABLE:
                health_status["performance"] = {
                    "request_count": application_state["request_count"],
                    "error_count": application_state["error_count"],
                    "error_rate": (
                        cast(int, application_state["error_count"]) /
                        cast(int, application_state["request_count"]) * 100
                        if cast(int, application_state["request_count"]) > 0
                        else 0
                    )
                }

            duration = time.time() - start_time
            health_status["response_time_ms"] = duration * 1000

            return health_status

        except Exception as err:
            logger.error(f"Health check error: {err}")
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "error": str(err),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
else:

    @app.get("/health")
    async def health_check(request: Request) -> Dict[str, Any]:
        """Basic health check endpoint"""
        return {
            "status": "healthy",
            "service": "DevOps Shield Backend",
            "version": "2.0.0",
            "environment": os.getenv("ENVIRONMENT", "development"),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


# WebSocket endpoint for real-time alerts
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """Real-time alert notifications via WebSocket"""
    await websocket_manager.connect(websocket)
    application_state["websocket_connections"] = len(
        websocket_manager.active_connections)

    try:
        while True:
            await websocket.receive_text()
            # Echo back or handle commands
            await websocket.send_json({
                "type": "pong",
                "message": "Connection active",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
    except WebSocketDisconnect:
        await websocket_manager.disconnect(websocket)
        application_state["websocket_connections"] = len(
            websocket_manager.active_connections)

# Mount static files for frontend
frontend_build_path = Path(__file__).parent.parent / "frontend" / "build"
static_dir = frontend_build_path / "static"

if frontend_build_path.exists() and static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    assets_dir = frontend_build_path / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")
    logger.info(f"Serving frontend static files from {frontend_build_path}")
else:
    logger.warning(
        f"Frontend build directory or static files not found at {frontend_build_path}")


@app.get("/manifest.json")
async def serve_manifest():
    """Serve the PWA manifest with correct MIME type"""
    manifest_path = frontend_build_path / "manifest.json"
    if manifest_path.exists():
        return FileResponse(str(manifest_path), media_type="application/manifest+json")
    return JSONResponse(status_code=404, content={"detail": "Manifest not found"})


@app.get("/sw.js")
async def serve_service_worker():
    """Serve service worker if present, otherwise 404"""
    sw_path = frontend_build_path / "sw.js"
    if sw_path.exists():
        return FileResponse(str(sw_path), media_type="application/javascript")
    return JSONResponse(status_code=404, content={"detail": "Service worker not found"})


@app.get("/favicon.ico")
async def serve_favicon():
    """Serve favicon with proper content type"""
    favicon_path = frontend_build_path / "favicon.ico"
    if favicon_path.exists():
        return FileResponse(str(favicon_path), media_type="image/x-icon")
    return JSONResponse(status_code=404, content={"detail": "Favicon not found"})

# API info endpoint (moved from root)


@app.get("/api/info")
async def api_info():
    """API information endpoint"""
    msg = "DevOps Fraud Shield API - Advanced CI/CD Security"
    return {
        "message": msg + " Platform",
        "status": "running",
        "version": "2.0.0",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "api_docs": "/docs",
        "redoc": "/redoc",
        "openapi": "/openapi.json",
        "health_check": "/health",
        "metrics": "/metrics",
        "features": {
            "security_monitoring": True,
            "fraud_detection": True,
            "blockchain_auditing": (
                os.getenv("BLOCKCHAIN_ENABLED", "false").lower() == "true"
            ),
            "real_time_alerts": True,
            "attack_simulation": True,
            "zero_trust_architecture": True
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# Root endpoint - serve React app


@app.get("/")
async def serve_frontend():
    """Serve the React frontend"""
    index_path = frontend_build_path / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    else:
        return JSONResponse(
            content={
                "message": "DevOps Fraud Shield API",
                "note": "Frontend not built. API is available at /api, /docs, and /health",
                "api_docs": "/docs"
            }
        )

# Metrics endpoint for Prometheus (only if available)
if PROMETHEUS_AVAILABLE:
    @app.get("/metrics")
    async def metrics():
        """Prometheus metrics endpoint"""
        try:
            # Update system metrics if psutil is available
            if PSUTIL_AVAILABLE and psutil and SYSTEM_MEMORY and SYSTEM_CPU:
                if hasattr(SYSTEM_MEMORY, 'set'):
                    SYSTEM_MEMORY.set(psutil.virtual_memory().used)  # type: ignore
                if hasattr(SYSTEM_CPU, 'set'):
                    SYSTEM_CPU.set(psutil.cpu_percent())  # type: ignore

            if generate_latest and callable(generate_latest):
                return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)  # type: ignore
            else:
                return Response("Metrics collection not available", status_code=503)
        except Exception as err:
            logger.error(f"Metrics collection failed: {err}")
            return Response("Metrics collection failed", status_code=500)


# Performance dashboard endpoint (only if rate limiting is available)
if limiter:
    @app.get("/api/performance/dashboard")
    @limiter.limit("30/minute")
    async def performance_dashboard(request: Request) -> Dict[str, Any]:
        """
        Comprehensive performance dashboard with detailed metrics
        """
        try:
            # Get performance metrics
            perf_metrics = (
                get_performance_metrics()
                if get_performance_metrics
                else {}
            )

            # Get database metrics
            db_metrics = {}
            try:
                from src.utils.database_pool import db_pool  # type: ignore
                if db_pool:
                    db_metrics = db_pool.get_performance_metrics()
            except Exception as err:
                logger.error(f"Database metrics error: {err}")
                db_metrics = {"error": str(err)}

            # System resource metrics (only if psutil is available)
            if PSUTIL_AVAILABLE and psutil:
                system_metrics = {
                    "memory": {
                        "total_gb": (
                            psutil.virtual_memory().total / 1024 / 1024 / 1024
                        ),
                        "available_gb": (
                            psutil.virtual_memory().available /
                            1024 / 1024 / 1024
                        ),
                        "used_percent": psutil.virtual_memory().percent,
                        "used_gb": (
                            psutil.virtual_memory().used / 1024 / 1024 / 1024
                        )
                    },
                    "cpu": {
                        "percent": psutil.cpu_percent(interval=1),
                        "count": psutil.cpu_count(),
                        "frequency_mhz": (
                            psutil.cpu_freq().current
                            if psutil.cpu_freq()
                            else 0
                        )
                    },
                    "disk": {
                        "total_gb": (
                            psutil.disk_usage('/').total / 1024 / 1024 / 1024
                        ),
                        "free_gb": (
                            psutil.disk_usage('/').free / 1024 / 1024 / 1024
                        ),
                        "used_percent": (
                            psutil.disk_usage('/').used /
                            psutil.disk_usage('/').total * 100
                        )
                    },
                    "network": {
                        "connections": len(psutil.net_connections()),
                        "bytes_sent": (
                            psutil.net_io_counters().bytes_sent
                            if psutil.net_io_counters()
                            else 0
                        ),
                        "bytes_recv": (
                            psutil.net_io_counters().bytes_recv
                            if psutil.net_io_counters()
                            else 0
                        )
                    }
                }
            else:
                system_metrics = {
                    "error": (
                        "System monitoring not available - "
                        "psutil not installed"
                    )
                }

            # Application metrics
            app_metrics = {
                "uptime_seconds": (
                    (datetime.now(timezone.utc) -
                     cast(datetime, application_state["startup_time"])).total_seconds()
                ),
                "request_count": application_state["request_count"],
                "error_count": application_state["error_count"],
                "error_rate": (
                    cast(int, application_state["error_count"]) /
                    cast(int, application_state["request_count"]) * 100
                    if cast(int, application_state["request_count"]) > 0
                    else 0
                ),
                "last_health_check": (
                    cast(datetime, application_state["last_health_check"]).isoformat()
                    if application_state["last_health_check"]
                    else None
                )
            }

            # Performance recommendations
            recommendations = []

            # Memory recommendations
            if (PSUTIL_AVAILABLE and
                    psutil and
                    cast(dict, system_metrics).get("memory", {}).get("used_percent", 0) > 80):
                recommendations.append(
                    "High memory usage detected. "
                    "Consider optimizing memory usage or increasing resources."
                )

            # CPU recommendations
            if (PSUTIL_AVAILABLE and
                    psutil and
                    cast(Dict[str, Any], system_metrics).get("cpu", {}).get("percent", 0) > 80):
                recommendations.append(
                    "High CPU usage detected. "
                    "Consider optimizing code or scaling horizontally."
                )

            # Database recommendations
            if float(cast(Dict[str, Any], db_metrics).get("avg_response_time_ms", 0)) > 1000:
                recommendations.append(
                    "Slow database queries detected. "
                    "Consider optimizing queries or adding indexes."
                )

            # Error rate recommendations
            if float(cast(float, app_metrics.get("error_rate", 0))) > 5:
                recommendations.append(
                    "High error rate detected. Check application logs for issues."
                )

            return {
                "timestamp": (
                    datetime.now(timezone.utc).isoformat()
                ),
                "status": (
                    "healthy"
                    if len(recommendations) == 0
                    else "warning"
                ),
                "performance_metrics": perf_metrics,
                "database_metrics": db_metrics,
                "system_metrics": system_metrics,
                "application_metrics": app_metrics,
                "recommendations": recommendations,
                "performance_score": calculate_performance_score(
                    system_metrics,
                    db_metrics,
                    app_metrics
                )
            }

        except Exception as err:
            logger.error(f"Performance dashboard error: {err}")
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "error": str(err),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )


def calculate_performance_score(
        system_metrics: Dict,
        db_metrics: Dict,
        app_metrics: Dict
) -> int:
    """Calculate overall performance score (0-100)"""
    score = 100

    # Memory score (0-30 points)
    memory_percent = system_metrics.get("memory", {}).get("used_percent", 0)
    if memory_percent > 90:
        score -= 30
    elif memory_percent > 80:
        score -= 20
    elif memory_percent > 70:
        score -= 10

    # CPU score (0-20 points)
    cpu_percent = system_metrics.get("cpu", {}).get("percent", 0)
    if cpu_percent > 90:
        score -= 20
    elif cpu_percent > 80:
        score -= 15
    elif cpu_percent > 70:
        score -= 10

    # Database score (0-30 points)
    db_response_time = db_metrics.get("avg_response_time_ms", 0)
    if db_response_time > 2000:
        score -= 30
    elif db_response_time > 1000:
        score -= 20
    elif db_response_time > 500:
        score -= 10

    # Error rate score (0-20 points)
    error_rate = app_metrics.get("error_rate", 0)
    if error_rate > 10:
        score -= 20
    elif error_rate > 5:
        score -= 15
    elif error_rate > 2:
        score -= 10
    elif error_rate > 1:
        score -= 5

    return max(0, score)


if limiter:
    # Performance reset endpoint
    @app.post("/api/performance/reset")
    @limiter.limit("10/minute")
    async def reset_performance(request: Request) -> Dict[str, Any]:
        """Reset performance metrics"""
        try:
            if reset_metrics:
                reset_metrics()

            application_state["request_count"] = 0
            application_state["error_count"] = 0
            application_state["last_health_check"] = None

            return {
                "status": "success",
                "message": "Performance metrics reset successfully",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        except Exception as err:
            logger.error(f"Performance reset error: {err}")
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "error": str(err),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
else:
    @app.post("/api/performance/reset")
    async def reset_performance(request: Request) -> Dict[str, Any]:
        """Reset performance metrics (without rate limiting)"""
        try:
            if reset_metrics:
                reset_metrics()

            application_state["request_count"] = 0
            application_state["error_count"] = 0
            application_state["last_health_check"] = None

            return {
                "status": "success",
                "message": "Performance metrics reset successfully (no limit)",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        except Exception as err:
            logger.error(f"Performance reset error: {err}")
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "error": str(err),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )


if limiter:
    @app.get("/api/security/audit")
    @limiter.limit("30/minute")
    async def security_audit(request: Request) -> Dict[str, Any]:
        """Security audit information (admin only)"""
        # In production, add proper authentication check
        client_ip = "127.0.0.1"
        if get_remote_address and callable(get_remote_address):
            client_ip = get_remote_address(request)  # type: ignore

        audit_info = {
            "security_features": {
                "rate_limiting": "enabled",
                "security_headers": security_modules_loaded,
                "request_validation": (
                    security_modules_loaded and
                    RequestValidationMiddleware is not None
                ),
                "ip_whitelist": (
                    os.getenv("IP_WHITELIST_ENABLED", "false")
                    .lower() == "true"
                ),
                "audit_logging": True
            },
            "recent_violations": (
                await security_audit_logger
                .get_recent_violations(limit=10)
            ),
            "blocked_ips": await security_audit_logger.get_blocked_ips(),
            "rate_limit_status": "active",
            "audit_timestamp": datetime.now(timezone.utc).isoformat()
        }

        security_audit_logger.log_security_audit_access(client_ip)
        return audit_info
else:
    @app.get("/api/security/audit")
    async def security_audit(request: Request) -> Dict[str, Any]:
        """Security audit information (admin only, no limit)"""
        client_ip = request.client.host if request.client else "unknown"

        audit_info = {
            "security_features": {
                "rate_limiting": "disabled",
                "security_headers": security_modules_loaded,
                "request_validation": (
                    security_modules_loaded and
                    RequestValidationMiddleware is not None
                ),
                "ip_whitelist": (
                    os.getenv("IP_WHITELIST_ENABLED", "false")
                    .lower() == "true"
                ),
                "audit_logging": True
            },
            "recent_violations": (
                await security_audit_logger
                .get_recent_violations(limit=10)
            ),
            "blocked_ips": await security_audit_logger.get_blocked_ips(),
            "rate_limit_status": "inactive",
            "audit_timestamp": datetime.now(timezone.utc).isoformat()
        }

        security_audit_logger.log_security_audit_access(client_ip)
        return audit_info


# Helper functions


async def check_database_health() -> Dict[str, Any]:
    """Check database connectivity and health"""
    try:
        # Implement actual database health check
        # For now, return mock data
        return {
            "status": "healthy",
            "connection_pool": "operational",
            "response_time_ms": "< 50",
            "last_check": datetime.now(timezone.utc).isoformat()
        }
    except Exception as err:
        logger.error(f"Database health check failed: {err}")
        return {
            "status": "unhealthy",
            "error": str(err),
            "last_check": datetime.now(timezone.utc).isoformat()
        }


async def check_database_status() -> Dict[str, Any]:
    """Detailed database status"""
    return await check_database_health()


async def check_blockchain_connectivity() -> bool:
    """Check blockchain connectivity"""
    try:
        if os.getenv("BLOCKCHAIN_ENABLED", "false").lower() == "true":
            # Implement actual blockchain connectivity check
            return True
        return False
    except Exception as err:
        logger.error(f"Blockchain connectivity check failed: {err}")
        return False


async def check_blockchain_status() -> Dict[str, Any]:
    """Detailed blockchain status"""
    try:
        if os.getenv("BLOCKCHAIN_ENABLED", "false").lower() == "true":
            return {
                "status": "connected",
                "network": os.getenv("ETHEREUM_NETWORK", "mainnet"),
                "last_block": "12345",
                "gas_price": "20 gwei",
                "last_check": datetime.now(timezone.utc).isoformat()
            }
        else:
            return {
                "status": "disabled",
                "message": "Blockchain features are disabled"
            }
    except Exception as err:
        logger.error(f"Blockchain status check failed: {err}")
        return {
            "status": "error",
            "error": str(err)
        }


async def check_external_services() -> Dict[str, Any]:
    """Check external service connectivity"""
    services = {}

    # Check GitHub API
    try:
        # Implement actual GitHub API check
        services["github"] = {"status": "healthy", "response_time_ms": "< 100"}
    except Exception as err:
        services["github"] = {"status": "unhealthy", "error": str(err)}

    # Check Slack webhook
    try:
        # Implement actual Slack webhook check
        services["slack"] = {
            "status": "healthy",
            "last_notification": datetime.now(timezone.utc).isoformat()
        }
    except Exception as err:
        services["slack"] = {"status": "unhealthy", "error": str(err)}

    return services


# Request ID middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add unique request ID to each request"""
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

# Performance monitoring middleware


@app.middleware("http")
async def performance_monitoring_middleware(request: Request, call_next):
    """Performance monitoring middleware"""
    start_time = time.time()

    # Update active connections
    if ACTIVE_CONNECTIONS:
        ACTIVE_CONNECTIONS.inc()

    try:
        response = await call_next(request)

        # Record metrics
        duration = time.time() - start_time
        if REQUEST_DURATION:
            REQUEST_DURATION.observe(duration)
        if REQUEST_COUNT:
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.url.path,
                status=response.status_code
            ).inc()

        # Add performance headers
        response.headers["X-Response-Time"] = f"{duration:.3f}s"
        response.headers["X-Request-ID"] = f"{int(time.time() * 1000)}"

        return response

    except Exception:
        application_state["error_count"] = cast(
            int, application_state["error_count"]) + 1
        if REQUEST_COUNT:
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.url.path,
                status="500"
            ).inc()
        raise
    finally:
        if ACTIVE_CONNECTIONS:
            ACTIVE_CONNECTIONS.dec()


# Graceful shutdown handling
def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    sig_msg = "Received signal"
    logger.info(
        f"{sig_msg} {signum}, initiating graceful shutdown..."
    )

    # Perform cleanup
    asyncio.create_task(shutdown_app())


async def shutdown_app():
    """Graceful shutdown tasks"""
    try:
        # Save application state
        logger.info("Saving application state...")

        # Close database connections
        logger.info("Closing database connections...")

        # Stop monitoring
        if performance_modules_loaded:
            if metrics_collector and hasattr(metrics_collector, 'stop_monitoring'):
                await metrics_collector.stop_monitoring()

        logger.info("Graceful shutdown completed")

    except Exception as err:
        logger.error(f"Shutdown error: {err}")


# Register signal handlers
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


# Server configuration
def create_server_config() -> Dict[str, Any]:
    """Create server configuration"""
    return {
        "host": os.getenv("HOST", "0.0.0.0"),
        "port": int(os.getenv("PORT", 8000)),
        "workers": int(os.getenv("WORKERS", 1)),
        "reload": False,  # Disable reload for stable operation
        "log_level": os.getenv("LOG_LEVEL", "info").lower(),
        "access_log": (
            os.getenv("ACCESS_LOG", "true").lower() == "true"
        ),
        "ssl_keyfile": os.getenv("SSL_KEYFILE"),
        "ssl_certfile": os.getenv("SSL_CERTFILE"),
        "timeout_keep_alive": int(
            os.getenv("TIMEOUT_KEEP_ALIVE", 65)
        ),
        "timeout_graceful_shutdown": int(
            os.getenv("TIMEOUT_GRACEFUL_SHUTDOWN", 30)
        )
    }


# Catch-all route for React Router (must be last)
@app.get("/{full_path:path}")
async def catch_all(full_path: str):
    """Catch-all route to serve React app for client-side routing"""
    # Don't intercept API routes, docs, or static files
    if full_path.startswith(("api/", "docs", "redoc", "openapi.json", "health", "metrics", "static/")):
        return JSONResponse(
            status_code=404,
            content={"detail": "Not found"}
        )

    # Serve index.html for all other routes (React Router)
    index_path = frontend_build_path / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    else:
        return JSONResponse(
            content={
                "message": "Frontend not available",
                "api_docs": "/docs"
            },
            status_code=404
        )


# Run server
if __name__ == "__main__":
    config = create_server_config()

    logger.info(
        f"Starting DevOps Fraud Shield Backend on {config['host']}:"
        f"{config['port']}"
    )
    logger.info(f"Environment: {os.getenv('ENVIRONMENT', 'development')}")
    logger.info(
        f"Security modules: "
        f"{'enabled' if security_modules_loaded else 'disabled'}"
    )
    logger.info(
        f"Performance monitoring: "
        f"{'enabled' if performance_modules_loaded else 'disabled'}"
    )

    uvicorn.run(
        app,
        host=config["host"],
        port=config["port"],
        workers=config["workers"],
        reload=config["reload"],
        log_level=config["log_level"],
        access_log=config["access_log"],
        ssl_keyfile=config["ssl_keyfile"],
        ssl_certfile=config["ssl_certfile"],
        timeout_keep_alive=config["timeout_keep_alive"],
        timeout_graceful_shutdown=config["timeout_graceful_shutdown"]
    )
