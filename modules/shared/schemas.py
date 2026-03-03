"""
shared pydantic schemas for inter-service communication
"""

from pydantic import BaseModel, Field


# ── context module ──────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    url: str
    params: list[str]
    waf: str = "none"
    form_method: str = "GET"  # GET or POST
    form_fields: list[str] = Field(default_factory=list)  # all required field names
    display_url: str = ""  # page where stored output appears (for stored XSS)


class ParamContext(BaseModel):
    reflects_in: str = "none"
    allowed_chars: list[str] = Field(default_factory=list)
    context_confidence: float = 0.0


# response is dict[str, ParamContext]


# ── payload-gen module ──────────────────────────────────────

class GenerateRequest(BaseModel):
    contexts: dict[str, ParamContext]
    waf: str = "none"
    max_payloads: int = 50


class GeneratedPayload(BaseModel):
    payload: str
    target_param: str
    context: str
    confidence: float
    waf_bypass: bool = False


class GenerateResponse(BaseModel):
    payloads: list[GeneratedPayload]


# ── fuzzer module ───────────────────────────────────────────

class FuzzPayload(BaseModel):
    payload: str
    target_param: str
    confidence: float = 0.0


class FuzzRequest(BaseModel):
    url: str
    payloads: list[FuzzPayload]
    verify_execution: bool = True
    timeout: int = 10000
    stored_mode: bool = False  # if True, submit to url but check display_url for reflection
    display_url: str = ""  # page to check for stored XSS output
    form_method: str = "GET"  # HTTP method for submission
    form_fields: dict[str, str] = Field(default_factory=dict)  # prefilled form fields (csrf, postId, etc.)
    # metadata for training data collection
    context: str | None = None  # context label (e.g., 'script_injection')
    waf: str | None = None  # waf type detected (e.g., 'cloudflare')
    allowed_chars: list[str] | None = None  # allowed special characters


class FuzzResult(BaseModel):
    payload: str
    target_param: str
    reflected: bool = False
    executed: bool = False
    vuln: bool = False
    type: str = ""
    evidence: dict = Field(default_factory=dict)


class FuzzResponse(BaseModel):
    results: list[FuzzResult]
