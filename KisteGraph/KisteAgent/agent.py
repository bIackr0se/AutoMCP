# ===== Import libraries =====
import json
import asyncio
import os
import re          # Added for regex operations
import whois         # pip install python-whois
import dns.resolver  # pip install dnspython
from typing import Any, Optional
from langgraph.graph import StateGraph, START, END
from langgraph.graph import MessagesState
from langchain_core.messages import SystemMessage, AIMessage, HumanMessage, ToolMessage
from langgraph.types import interrupt

# --- security mitigations (paper Sec 5); helpers live in mitigations.py, which
# must be co-deployed in the same directory as this agent. The try/except keeps
# the import working whether agent.py is loaded as a script or as a package module. ---
try:
    from mitigations import (
        validate_scan_target,            # M1 (Sec 5.1) resolve-then-validate target gate
        extract_indicators_from_alerts,  # M1 (Sec 5.1) origin-tie: indicators of retrieved alerts
        build_analyzer_messages,         # M3 (Sec 5.3) instruction-data separation
        severity_aware_retain,           # M2 (Sec 5.2) severity-aware retention merge
        _HIGH_SEVERITIES,                # M2 reserve-query severity values  >>> SCHEMA: verify
    )
except ImportError:
    from .mitigations import (
        validate_scan_target,
        extract_indicators_from_alerts,
        build_analyzer_messages,
        severity_aware_retain,
        _HIGH_SEVERITIES,
    )
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field, field_validator, ValidationError
from mcp.server.fastmcp import FastMCP
from elasticsearch import AsyncElasticsearch
from contextlib import asynccontextmanager
from langchain_ollama import ChatOllama
from langchain_groq import ChatGroq
from pathlib import Path
import socket
import shutil
import ipaddress
from urllib.parse import urlparse
import requests
import urllib3

# ====================
# LLM BACKEND CONFIGURATION
# ====================

# Default settings
DEFAULT_MODEL = "qwen2.5:3b"
DEFAULT_BACKEND = "ollama"

# Cache for the selected backend (set once at startup)
_selected_backend: Optional[str] = None

def get_llm_backend() -> str:
    """
    Get the selected LLM backend. Prompts user for selection on first call.
    Returns 'ollama' (default) or 'groq'.
    """
    global _selected_backend
    
    if _selected_backend is not None:
        return _selected_backend
    
    # Check for environment variable override
    env_backend = os.environ.get("LLM_BACKEND", "").lower()
    if env_backend in ["ollama", "groq"]:
        _selected_backend = env_backend
        print(f"[LLM] Using backend from environment: {_selected_backend}")
        return _selected_backend
    
    # Prompt user for selection
    print("\n" + "=" * 50)
    print("🤖 LLM Backend Selection")
    print("=" * 50)
    print(f"Default model: {DEFAULT_MODEL}")
    print("\nAvailable backends:")
    print("  1. ollama (default) - Local LLM via Ollama")
    print("  2. groq - Cloud LLM via Groq API")
    print("\nPress Enter for default (ollama), or type 'groq':")
    
    try:
        choice = input(">>> ").strip().lower()
    except EOFError:
        # Non-interactive mode, use default
        choice = ""
    
    if choice == "groq" or choice == "2":
        _selected_backend = "groq"
        # Verify GROQ_API_KEY is set
        if not os.environ.get("GROQ_API_KEY"):
            print("⚠️  Warning: GROQ_API_KEY not found. API calls will fail. Please set it as environment variable.")
    else:
        _selected_backend = "ollama"
    
    print(f"[LLM] Selected backend: {_selected_backend}")
    print("=" * 50 + "\n")
    
    return _selected_backend

def get_llm(temperature: float = 0, model: Optional[str] = None):
    """
    Factory function to create the appropriate LLM instance based on user selection.
    Supports ollama (default) or groq as an alternative backend.
    
    Args:
        temperature: Temperature setting for the LLM (default: 0)
        model: Model name (default: qwen2.5:3b for both backends)
    
    Returns:
        ChatOllama or ChatGroq instance
    
    Raises:
        ValueError: If groq backend is selected but GROQ_API_KEY is not set
    """
    backend = get_llm_backend()
    model_name = model or DEFAULT_MODEL
    
    if backend == "groq":
        if not os.environ.get("GROQ_API_KEY"):
            raise ValueError("GROQ_API_KEY environment variable is required when using groq backend")
        return ChatGroq(model=model_name, temperature=temperature)
    else:
        return ChatOllama(model=model_name, temperature=temperature)

# ====================
# TOOL DEFINITIONS (PYDANTIC)
# ====================

class chat_mode(BaseModel):
    """
    Use this tool for:
    1. Analyzing, explaining, or interpreting the logs/data ALREADY retrieved in the conversation.
    2. Answering general cybersecurity questions.
    3. Greetings or small talk.
    
    DO NOT use this if the user specifically asks to perform a NEW search in the database.
    """
    request: str = Field(
        description="The user's question or comment regarding the existing data or general topic.", 
        default="Analyze this"
    )

class custom_query_mode(BaseModel):
    """
    Use this tool ONLY when the user asks to PERFORM A NEW SEARCH or QUERY in the database.
    Triggers: 'Find alerts', 'Check this IP', 'Search for...', 'Show logs from...'
    
    DO NOT use this if the user is just asking about the logs currently visible in the chat.
    """
    request: str = Field(
        description="The specific search criteria (e.g., 'Check IP 1.2.3.4').", 
        default="Check latest alerts"
    )

class standby_mode(BaseModel):
    """
    Use this tool ONLY when the user explicitly asks to wait, watch, or monitor for NEW incoming alerts.
    """
    request: str = Field(description="Ignored.", default="switch")


class counter_recon_mode(BaseModel):
    """
    Use this tool when the user asks to investigate an EXTERNAL IP address or Domain using tools like NMAP, WHOIS, DIG, CURL.
    Triggers: 'Scan this IP', 'Who owns this domain?', 'Check DNS records for...', 'Investigate attacker infrastructure'
    """
    target: str = Field(
        description="The specific IP address or Domain to scan. EXTRACT this from user input.", 
        default="unknown"
    )

tools = [chat_mode, standby_mode, custom_query_mode, counter_recon_mode]

# ====================

# OpenAI / Groq API Key Setup
def _set_env(var: str):
    if not os.environ.get(var):
        # Use environment variable fallback instead of blocking getpass
        # getpass.getpass() would block the event loop, so we skip it in async context
        default_value = f"<{var}_not_set>"
        os.environ[var] = default_value
        print(f"Warning: {var} not found. Please set it as environment variable.")

# Only try to set GROQ_API_KEY if it's not already set
if not os.environ.get("GROQ_API_KEY"):
    print("Warning: GROQ_API_KEY not found. Please set it as environment variable.")

# ====================
ES_HOST = "https://141.79.66.103:9200"
# ES_HOST = "http://localhost:9200"
ES_ALERTS_INDEX = ".internal.alerts-security.alerts-default*" # Index for security alerts
ES_INTEL_INDEX = "otx_pulses_minimal" # Index for threat intelligence
ES_API_KEY = os.getenv("ES_API_KEY") # Elasticsearch API Key from environment variable
LOCAL_TIMEZONE = 1
LOCAL_TZINFO = timezone(timedelta(hours=LOCAL_TIMEZONE)) # For correcting local time to UTC
ES_USERNAME = os.getenv("ES_USERNAME")
ES_PASSWORD = os.getenv("ES_PASSWORD")
# ====================

# Data Type Class for Elastic Query
class QueryAlertParams(BaseModel):

    # Selected fields
    start_date        : Optional[str]       = None
    end_date          : Optional[str]       = None
    aggregation       : Optional[str]       = None
    description       : Optional[str]       = None
    severity          : Optional[list[str]] = None
    rule_name         : Optional[str]       = None
    mitre_attack_info : Optional[list[str]] = None
    host_ip           : Optional[str]       = None

    # Fill empty spaces with 'None'.
    @field_validator('*', mode='before')
    def empty_str_to_none(cls, v):
        if v == "": return None
        return v
    
    @field_validator('start_date', 'end_date')
    def validate_and_convert_to_utc(cls, value):
        if value is None: 
            return value
        
        try:
            # Turn the input string into 'datetime' object
            dt = datetime.fromisoformat(value)
            
            # Mark the input time as UTC+1
            dt_local_aware = dt.replace(tzinfo=LOCAL_TZINFO)
            
            # Turn this time into UTC
            dt_utc = dt_local_aware.astimezone(timezone.utc)

            # Return in 'Z' format for Elastics
            return dt_utc.isoformat().replace('+00:00', 'Z')

        except ValueError:
            raise ValueError(f"Invalid date format: '{value}'. Use 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SS'.")
        
    # Handle aggregations
    @field_validator('aggregation')
    def validate_aggregation(cls, value):
        if value is None: return value
        valid_aggregations = ["hourly", "daily", "weekly", "monthly"]
        if value not in valid_aggregations:
            raise ValueError(f"Invalid aggregation. Use one of: {valid_aggregations}")
        return value

# ====================

# State Class
class AppState(MessagesState):
    # Optional dictionary to store structured attack analysis data
    attack_analysis: Optional[dict]
    # M1 (Sec 5.1) origin-tie: indicator addresses (source.ip / host.ip) of the
    # most recently retrieved alerts. Written by execute_elastic_query and read
    # by counter_recon (via _extract_originating_indicator) so a scan target is
    # bound to the alert that triggered the investigation. Absent until a query
    # retrieves alerts, so a scan with no preceding retrieval fails closed.
    originating_indicators: Optional[list[str]]

# ====================

# Initialize MCP Server
mcp = FastMCP("mcp_server")

# Initialize Elastic Client
@asynccontextmanager
async def get_elastic_client(state: AppState):
    elastic_client = await asyncio.to_thread(
        AsyncElasticsearch,
        ES_HOST, 
        basic_auth=(ES_USERNAME, ES_PASSWORD),
        verify_certs=False
    )
    
    try:
        yield elastic_client
    finally:
        await elastic_client.close()

# ====================

async def execute_elastic_query(state: AppState, index: str = ES_ALERTS_INDEX) -> dict[str, Any] | None:

    # Retrieve parameters from State (from the last LLM message)
    last_message = state["messages"][-1]
    
    try:
        content = last_message.content
        raw_params = json.loads(content)
        params = QueryAlertParams(**raw_params)
        
    except (json.JSONDecodeError, ValidationError):
        # Return error if parameters cannot be parsed
        return {"messages": [AIMessage(content="Error: Could not parse query parameters.")]}

    DESIRED_OUTPUT_FIELDS = [
        "kibana.alert.rule.execution.timestamp",
        "kibana.alert.rule.parameters.severity",
        "kibana.alert.rule.name",
        "kibana.alert.rule.parameters.description",
        "kibana.alert.rule.parameters.threat",
        "host.ip"
    ]
    
    query = {"query": {"bool": {"must": []}}}
    filters = query["query"]["bool"]["must"]
    
    # Dates
    if params.start_date or params.end_date:
        date_range = {}
        if params.start_date: date_range["gte"] = params.start_date
        if params.end_date: date_range["lte"] = params.end_date
        filters.append({"range": {"kibana.alert.rule.execution.timestamp": date_range}})
    
    # Description
    if params.description:
        filters.append({"match": {"kibana.alert.rule.parameters.description": params.description}})
    
    # Severity
    if params.severity:
        severity_val = params.severity if isinstance(params.severity, list) else [params.severity]
        filters.append({"terms": {"kibana.alert.rule.parameters.severity": severity_val}})
    
    # Rule name
    if params.rule_name:
        filters.append({"match": {"kibana.alert.rule.name": params.rule_name}})

    if params.host_ip:
        filters.append({"match": {"host.ip": params.host_ip}})

    if params.mitre_attack_info:
        mitre_val = params.mitre_attack_info if isinstance(params.mitre_attack_info, list) else [params.mitre_attack_info]
        filters.append({
            "terms": {
                "kibana.alert.rule.parameters.threat" : mitre_val
            }
        })

    # Aggregations logic
    if params.aggregation:
        interval_mapping = {"hourly": "1h", "daily": "1d", "weekly": "1w", "monthly": "1M"}
        es_interval = interval_mapping.get(params.aggregation, "1d")
        query["aggs"] = {
            "time_series": {
                "date_histogram": {"field": "kibana.alert.rule.execution.timestamp", 
                                   "calendar_interval": es_interval, 
                                   "min_doc_count": 1},
            }
        }
        query["size"] = 0
    else:
        query["sort"] = [{"kibana.alert.rule.execution.timestamp": "desc"}]
        query["size"] = 3
        query["_source"] = DESIRED_OUTPUT_FIELDS

    print(f"ES QUERY on {index}: {json.dumps(query)}")

    response = None
    
    reserve_hits = []
    async with get_elastic_client(state) as client:
        try:
            response = await client.search(index=index, body=query)
        except Exception as e:
            return {"messages": [AIMessage(content=f"Error querying Elasticsearch: {str(e)}")]}
        # MITIGATION M2 (Sec 5.2): one bounded reserve query for high-severity
        # alerts, merged below so a critical alert is not displaced by benign
        # volume. It inherits the main query's context filters (host, rule, date)
        # so the reserve stays scoped to the user's request, then adds the
        # severity constraint. Safe fallback: on error or empty reserve, retention
        # falls back to recency-only (the original behaviour).
        if not params.aggregation:
            try:
                # Inherit the main query's context filters but drop any severity
                # clause, so the high-severity reserve is not ANDed into an
                # impossible query when the user filtered on a non-high severity.
                context_filters = [f for f in filters if not (
                    isinstance(f, dict) and "kibana.alert.rule.parameters.severity" in f.get("terms", {})
                )]
                reserve_query = {
                    "query": {"bool": {"must": context_filters + [
                        {"terms": {"kibana.alert.rule.parameters.severity": _HIGH_SEVERITIES}}
                    ]}},
                    "sort": [{"kibana.alert.rule.execution.timestamp": "desc"}],
                    "size": 2,
                    "_source": DESIRED_OUTPUT_FIELDS,
                }
                reserve_resp = await client.search(index=index, body=reserve_query)
                reserve_hits = [h.get("_source") for h in reserve_resp.get("hits", {}).get("hits", []) if h.get("_source")]
            except Exception:
                reserve_hits = []

    # Process and return results
    processed_data = {}

    if params.aggregation:
        processed_data['aggregations'] = response.get('aggregations', {})
        processed_data['total_hits'] = response.get('hits', {}).get('total', {}).get('value', 0)
    
    alert_indicators = None
    if params.aggregation:
        pass
    else:
        hits = response.get('hits', {}).get('hits', [])
        clean_alerts = [hit.get('_source') for hit in hits if hit.get('_source')]
        # M2 (Sec 5.2): reserve high-severity slots ahead of recency.
        clean_alerts = severity_aware_retain(clean_alerts, reserve_hits, size=3)

        processed_data['total_hits_found'] = response.get('hits', {}).get('total', {}).get('value', 0)
        processed_data['hits_returned'] = len(clean_alerts)
        processed_data['alerts'] = clean_alerts

        # M1 (Sec 5.1) origin-tie: thread the structured indicators of the
        # retrieved alerts into state so counter_recon can bind a scan target to
        # the alert that triggered the investigation.
        alert_indicators = extract_indicators_from_alerts(clean_alerts)

    structured_response = {
        "query_parameters": params.model_dump(exclude_none=True),
        "data": processed_data
    }

    result = {
        "messages": [
            AIMessage(
                content= "Elastic Query Result:\n" + json.dumps(structured_response, indent=2, default=str)
            )
        ]
    }
    # Only an alert retrieval (not an aggregation) defines a fresh originating
    # alert; aggregation leaves any prior indicators in state untouched.
    if alert_indicators is not None:
        result["originating_indicators"] = alert_indicators
    return result

async def query_analyzer(state: AppState):
    query_result = state["messages"][-1].content

    # MITIGATION M3 (Sec 5.3): instruction-data separation. The trusted analyst
    # instruction stays in the system role; untrusted alert content goes in the
    # user role inside <ALERT_DATA> delimiters with a "data, not instructions"
    # directive (see build_analyzer_messages). Replaces the old
    # `sys_msg + query_result` concatenation that let an instruction planted in
    # an alert field be read as guidance.
    llm = get_llm()
    response = await llm.ainvoke(build_analyzer_messages(query_result))

    return {"messages": [AIMessage(content=response.content)]}

# >>> GATE (Sec 5.3, defense-in-depth): channel separation above is the primary
# fix; the autonomous standby path (query_analyzer_S) should also regain a
# human-review interrupt before a summary becomes a verdict. Add an interrupt()
# node on the _S branch in the graph builder and test under langgraph before
# enabling (it changes the standby execution model).


async def generate_elastic_query(state: AppState):
    user_prompt = "Show me the latest security alerts from the last 24 hours"

    for msg in reversed(state["messages"]):
        if isinstance(msg, HumanMessage):
            user_prompt = msg.content
            break

    data_schema_json = QueryAlertParams.model_json_schema()
    current_date = datetime.now().strftime("%Y-%m-%d")

    correct_examples = """
    Correct Examples:
        1) User Question: "Can you check all the alerts genereated within 3 weeks prior to see if there is a potential ransomware attack?"
        1) Generated Query: {
        "start_date": "2025-10-19T23:00:00Z",
        "severity": [
            "low",
            "medium",
            "high"
        ]
        }

        2) User Question : "Okay, what about logs that have 'TA0002' MITRE tactic ID? Do they correlate between each other? And what is this tactic ID means? What kind of attacks can I expect in the future?"
        2) Generated Query: {
        "mitre_tactic_id": [
            "TA0002"
        ]
        }

        3) User Question: "Can you investigate different logs that has 'medium' severity and tell me possible threats?"
        3) Generated Query:{
        "severity": [
            "medium"
        ]
        }
        """

    sys_msg = f"""
    You are an expert at extracting structured information. 
    Analyze the user's question and generate a JSON object with parameters for the `execute_elastic_query` tool.

    Tool Parameters Schema:
    {json.dumps(data_schema_json, indent=2)}

    Important Rules to Follow:
        1. Current date is ({current_date}). If the user asks for "last week", "yesterday", etc., calculate the time and date range based on today's date.
        2. If a parameter is not mentioned, omit it from the JSON.
        3. If the user asks for multiple severities (e.g., "medium or high"), provide them as a JSON list. Example: ["medium", "high"]
        4. The response MUST be a FLAT JSON object that ONLY contains the VALUE of the parameters.
        5. DO NOT include schema keywords like 'type', 'title', 'anyOf', or 'default' in the final JSON output.
        6. If the question cannot be answered using the tool (e.g., general knowledge), return an empty JSON object.
        7. Respond ONLY with the JSON object.
    
    {correct_examples}
    """

    human_msg = HumanMessage(content=f"User Question: '{user_prompt}'")

    llm = get_llm()
    
    response = await llm.ainvoke([sys_msg, human_msg])
    response_content = response.content

    try:
        params_dict = json.loads(response_content)
        
        validated_obj = QueryAlertParams(**params_dict)
        final_json_str = json.dumps(validated_obj.model_dump(exclude_none=True))
        
        return {"messages": [AIMessage(content=final_json_str)]}
    
    except (json.JSONDecodeError, ValidationError) as e:
        return {"messages": [AIMessage(content=f"Error parsing parameters: {str(e)} | Raw Output: {response_content}")]}


# ====================
# MODE HANDLERS
# ====================

def chat_mode(state: AppState):
    messages = []
    last_message = state["messages"][-1]
    
    initial_request = None

    # Handle Tool Call Logic
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "chat_mode":
                messages.append(
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        content="Successfully switched to Chat Mode."
                    )
                )
                initial_request = tool_call["args"].get("request")

    messages.append(AIMessage(content="Switched to Chat Mode."))

    # Inject the user's intent into the conversation stream
    if initial_request and initial_request != "switch":
        messages.append(HumanMessage(content=initial_request))
    
    return {"messages": messages}


def custom_query_mode(state: AppState):
    messages = []
    last_message = state["messages"][-1]
    initial_request = None

    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "custom_query_mode":
                messages.append(
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        content="Successfully switched to Custom Query Mode."
                    )
                )
                initial_request = tool_call["args"].get("request")
    
    messages.append(AIMessage(content="Switched to Custom Query Mode."))

    if initial_request and initial_request != "switch":
        messages.append(HumanMessage(content=initial_request))
    
    return {"messages": messages}


def standby_mode(state: AppState):
    messages = []
    last_message = state["messages"][-1]
    
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "standby_mode":
                messages.append(
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        content="Successfully switched to Standby Mode."
                    )
                )
    
    messages.append(AIMessage(content="Welcome to Standby Mode. Waiting for security alerts..."))
    
    return {"messages": messages}


# Suppress SSL warnings for self-signed certificates (common in reconnaissance)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- HELPER FUNCTIONS ---

def recursive_limit(data, limit=5):
    """
    Recursively limits the size of lists in a JSON object to prevent token overflow.
    Adds a '... (x more)' string if truncated.
    """
    if isinstance(data, dict):
        return {k: recursive_limit(v, limit) for k, v in data.items()}
    elif isinstance(data, list):
        trimmed = data[:limit]
        processed = [recursive_limit(item, limit) for item in trimmed]
        if len(data) > limit:
            processed.append(f"... ({len(data) - limit} more items truncated)")
        return processed
    return data

# --- ASYNC MODULES ---

async def run_otx_scan(target, api_key):
    """Fetches Threat Intelligence from AlienVault OTX (Smart Endpoint)."""
    try:
        ipaddress.ip_address(target)
        endpoint_type = "IPv4"
    except ValueError:
        endpoint_type = "domain"

    url = f"https://otx.alienvault.com/api/v1/indicators/{endpoint_type}/{target}/general"
    headers = {'X-OTX-API-KEY': api_key}
    
    try:
        response = await asyncio.to_thread(requests.get, url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            full_data = response.json()
            
            target_keys = ["reputation", "asn", "country_name", "city", "pulse_info", "validation"]
            filtered = {k: full_data.get(k) for k in target_keys}
            return {"source": "AlienVault OTX", "data": recursive_limit(filtered, limit=5)}
            
        elif response.status_code == 404:
             return {"source": "AlienVault OTX", "status": "No Intel Found (404) - Target is clean or unknown."}
             
        elif response.status_code == 400:
             return {"source": "AlienVault OTX", "error": f"Bad Request (400). Endpoint: {endpoint_type}"}
             
        return {"source": "AlienVault OTX", "error": f"API Status Code {response.status_code}"}
        
    except Exception as e:
        return {"source": "AlienVault OTX", "error": str(e)}

async def run_dns_scan(target):
    """Performs Smart DNS Lookup (PTR for IP, A/MX for Domain)."""
    results = {"type": "UNKNOWN", "reverse_lookup": None, "records": {}}
    
    # 1. Identify Type
    try:
        ipaddress.ip_address(target)
        is_ip = True
        results["type"] = "IP"
    except ValueError:
        is_ip = False
        results["type"] = "DOMAIN"

    try:
        if is_ip:
            # Reverse DNS (PTR)
            try:
                hostname, _, _ = await asyncio.to_thread(socket.gethostbyaddr, target)
                results["reverse_lookup"] = hostname
            except socket.herror:
                results["reverse_lookup"] = "NXDOMAIN (No PTR Record Found)"
        else:
            # Domain Records
            resolver = dns.resolver.Resolver()
            resolver.timeout = 4.0
            resolver.lifetime = 4.0
            
            # A Record
            try:
                ans = await asyncio.to_thread(resolver.resolve, target, 'A')
                results["records"]["A"] = [r.to_text() for r in ans]
            except: results["records"]["A"] = []
            
            # MX Record
            try:
                ans = await asyncio.to_thread(resolver.resolve, target, 'MX')
                results["records"]["MX"] = [f"{r.exchange.to_text()} (Pri: {r.preference})" for r in ans]
            except: results["records"]["MX"] = []
            
    except Exception as e:
        results["error"] = str(e)
    return results

async def run_whois_scan(target):
    """Fetches Domain/IP Registration Info."""
    try:
        # Run synchronous whois in a thread
        w = await asyncio.to_thread(whois.whois, target)
        
        # Normalize data (whois libs can return lists or strings)
        org = w.org[0] if isinstance(w.org, list) else w.org
        country = w.country[0] if isinstance(w.country, list) else w.country
        
        return {
            "organization": org if org else "Unknown/Redacted",
            "country": country,
            "creation_date": str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
            "registrar": w.registrar[0] if isinstance(w.registrar, list) else w.registrar
        }
    except Exception as e:
        # Common to fail on IPs or specific TLDs
        return {"status": "WHOIS Lookup Failed or Timed Out", "details": str(e)}

async def run_nmap_scan(target):
    """Performs Active Port Scanning via Subprocess."""
    nmap_path = await asyncio.to_thread(shutil.which, "nmap")
    if not nmap_path:
        return {"error": "Nmap tool not found in system PATH. Active scan skipped."}
    
    try:
        # Flags: -Pn (No ping), --top-ports 50 (Speed), -T4 (Aggressive timing), --open (Only open ports)
        cmd = ["nmap", "-Pn", "--top-ports", "50", "-T4", "--open", target]
        
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        
        # Timeout after 45 seconds to prevent hanging the agent
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=45)
            
            if process.returncode == 0:
                raw = stdout.decode().strip()
                # Parse output for cleaner JSON
                open_ports = []
                for line in raw.split('\n'):
                    if "/tcp" in line and "open" in line:
                        parts = line.split()
                        open_ports.append(f"{parts[0]} ({parts[2]})") # e.g. "80/tcp (http)"
                
                return {
                    "tool": "Nmap", 
                    "status": "Completed", 
                    "open_ports": open_ports if open_ports else "None found (Filtered/Closed)",
                    "raw_summary": raw[:600] # Limit char count
                }
            else:
                return {"error": "Nmap process failed", "details": stderr.decode()}
                
        except asyncio.TimeoutError:
            try: process.kill() 
            except: pass
            return {"error": "Scan Timed Out (>45s)"}
            
    except Exception as e:
        return {"error": str(e)}

async def run_http_scan(target):
    """Fingerprints Web Server Headers with Browser Masquerading."""
    results = {"status": "Unreachable", "headers": {}}
    
    url = target if target.startswith("http") else f"https://{target}"
    
    fake_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
    }

    try:
        resp = await asyncio.to_thread(requests.head, url, headers=fake_headers, verify=False, timeout=10)
        results["status"] = resp.status_code
        results["url"] = url
        
        interesting = ["Server", "X-Powered-By", "Content-Type", "Set-Cookie"]
        for k, v in resp.headers.items():
            if k in interesting:
                results["headers"][k] = v
                
    except requests.exceptions.SSLError:
        if url.startswith("https"):
            try:
                http_url = url.replace("https", "http")
                resp = await asyncio.to_thread(requests.head, http_url, headers=fake_headers, timeout=10)
                results["status"] = resp.status_code
                results["url"] = http_url
                results["headers"]["Server"] = resp.headers.get("Server", "Unknown")
            except: pass
    except Exception as e:
        results["error_detail"] = str(e)
        pass 
        
    return results

# --- MAIN AGENT TOOL ---

def _extract_originating_indicator(state: AppState):
    """MITIGATION M1 helper (Sec 5.1). Return the indicator addresses of the
    alert(s) that triggered this investigation, used to bind the scan target.
    These are threaded into state by execute_elastic_query from the structured
    fields (source.ip / host.ip) of the retrieved alerts. Returns None/empty when
    no alert was retrieved, in which case counter_recon fails closed (a scan
    unprompted by a retrieved alert is refused), matching Sec 5.1."""
    return state.get("originating_indicators")


async def counter_recon(state: AppState):
    """
    Orchestrates the active/passive reconnaissance flow.
    Runs parallel scanners -> Calls LLM internally -> Returns JSON + Analysis.
    """
    messages = []
    target = None
    
    last_message = state["messages"][-1]
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "counter_recon_mode":
                target = tool_call["args"].get("target")
                messages.append(ToolMessage(tool_call_id=tool_call["id"], content=f"Scanning target: {target}..."))
                break
    
    # MITIGATION M1 (Sec 5.1): the target comes ONLY from the typed router
    # argument. The previous free-text IPv4 extraction from recent messages is
    # removed, so an address appearing anywhere in chat/alert text is no longer a
    # scan target.

    # Resolve-then-validate: reject unless every resolved address is outside the
    # deny-list (private/loopback/link-local/cloud-metadata/OT) AND the target
    # matches an originating alert's indicator (see validate_scan_target).
    originating_indicators = _extract_originating_indicator(state)
    allowed, reason = validate_scan_target(target, originating_indicators)
    if not allowed:
        return {"messages": messages + [AIMessage(content=f"Scan refused by target validation: {reason}.")]}

    print(f"\n[AGENT] 🛡️ Starting 'Voltran' Reconnaissance for: {target}")

    API_KEY = '3c6d310486f1b6485879d2865d0b9d2f4113c8e97266f288abe8670a810e6f06'
    
    results = await asyncio.gather(
        run_otx_scan(target, API_KEY),
        run_dns_scan(target),
        run_whois_scan(target),
        run_nmap_scan(target),
        run_http_scan(target)
    )

    recon_report = {
        "target": target,
        "threat_intel": results[0],
        "dns": results[1],
        "whois": results[2],
        "nmap": results[3],
        "http": results[4]
    }

    json_output = json.dumps(recon_report, indent=2)

    print("[AGENT] 🧠 Analyzing data with internal LLM...")
    
    llm = get_llm()
    
    system_prompt = """You are a Tier-3 SOC Analyst. 
    Analyze the provided Reconnaissance Data JSON.
    
    Output Format:
    1. 🛡️ **Verdict**: Safe / Suspicious / Malicious
    2. 🔍 **Key Findings**: (Open ports, OTX pulses, unexpected headers, missing DNS)
    3. 💡 **Correlation**: How do these findings relate?
    4. 🚀 **Action**: Block IP / Investigate Further / Ignore
    """
    
    user_content = f"TARGET: {target}\n\nDATA:\n```json\n{json_output}\n```"
    
    analysis_response = await llm.ainvoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_content)
    ])

    final_output = (
        f"### 📡 RECONNAISSANCE DATA (RAW)\n"
        f"```json\n{json_output}\n```\n\n"
        f"---\n\n"
        f"### 🧠 INTELLIGENCE ANALYSIS\n"
        f"{analysis_response.content}"
    )
    
    messages.append(AIMessage(content=final_output))
    
    print("[AGENT] ✅ Analysis Complete. Returning full report.")
    
    return {"messages": messages}

# ====================

# Function to get user prompt if needed.
# def user_prompt(state: AppState):
#     """We get user input here."""
#     prompt = interrupt("Your prompt:")
#     return {"messages": [HumanMessage(content=prompt)]}

# ====================

async def call_llm(state: AppState):
    """
    We call the LLM and pass the system prompt and user prompt in it to get an answer.
    """
    llm = get_llm()
    
    sys_msg = SystemMessage(
        content = f"""
            ROLE & OBJECTIVE
                You are an expert Cybersecurity Data Analyst Assistant. 

                RULES
                1. Data Priority: Base all analysis strictly on the logs provided.
                2. Missing Data: Ask the user to run a query if data is missing.
                3. Tone: Professional, concise, alert-oriented.
            """
    )
    
    # Only send last 10 messages
    recent_messages = state["messages"][-10:] if len(state["messages"]) > 10 else state["messages"]
    response = await llm.ainvoke([sys_msg] + recent_messages)

    return {"messages": [response]}

# ====================

async def last_alert(state: AppState, alert_index: str= ES_ALERTS_INDEX):
    """Returns the latest alert using the shared client configuration"""

    latest_alert_query = {
        "size": 1,
        "sort": [{"kibana.alert.rule.execution.timestamp": "desc"}],
        "_source": ["kibana.alert.rule.execution.timestamp", "kibana.alert.rule.name"]
    }

    try:
        async with get_elastic_client(state) as client:
            last_data = await client.search(index=alert_index, body=latest_alert_query)
            last_hits = last_data.get('hits', {}).get('hits', [])

            if not last_hits:
                return False
            
            last_alert = last_hits[0].get('_source', {})
            return last_alert
    
    except Exception as e:
        print(f"Error checking last alert: {e}")
        return False

async def wait_alerts(state: AppState):
    """
    Waits for security alerts in Standby Mode.
    Loops indefinitely until a new alert is found.
    """    
    while True:
        last_alert_1 = await last_alert(state)
        await asyncio.sleep(5)
        last_alert_2 = await last_alert(state)

        if last_alert_1 != last_alert_2:
            return {"messages": [SystemMessage(content="new_alerts"), AIMessage(content= "{}")]}
        else:
            continue


# ====================
llm = get_llm()
llm_with_tools = llm.bind_tools(tools)
sys_msg = SystemMessage(
    content=(
        "You are an intelligent orchestration assistant. "
        "Your task is to analyze the conversation history and route the user to the correct tool.\n\n"
        
        "DECISION LOGIC:\n"
        "1. NEW DATA (custom_query_mode): Fetch/Search NEW data from DB (e.g., 'Check IP 1.1.1.1', 'Show last 5 alerts').\n"
        "2. ANALYSIS (chat_mode): Explain/Interpret ALREADY RETRIEVED data or general chat.\n"
        "3. ACTIVE RECON (counter_recon_mode): Use active tools (Nmap/Whois/Dig) on an external Target IP/Domain.\n"
        "4. MONITORING (standby_mode): Explicit waiting/monitoring/standby requests.\n\n"
        
        "You MUST call one of the tools. Do not reply with text."
    )
)

# ====================

async def assistant(state: AppState):

    prompt_text = interrupt("Main Menu - Your command:")
    new_message = HumanMessage(content=prompt_text)
    
    # Optimization: Use sys_msg + last few messages + new message
    recent_messages = state["messages"][-10:] if len(state["messages"]) > 10 else state["messages"]
    all_messages = [sys_msg] + recent_messages + [new_message]
        
    response = await llm_with_tools.ainvoke(all_messages)
        
    return {"messages": [new_message, response]}

# ====================

def route_mechanism(state: AppState):
    last_message = state["messages"][-1]
    
    # If there is a tool call
    if hasattr(last_message, "tool_calls") and len(last_message.tool_calls) > 0:
        tool_name = last_message.tool_calls[0]["name"]
        return tool_name

    return END

# ====================
# GRAPH CONSTRUCTION
# ====================

builder = StateGraph(AppState)

# Add Nodes
builder.add_node("assistant", assistant)
builder.add_node("chat_mode", chat_mode)
builder.add_node("standby_mode", standby_mode)
builder.add_node("custom_query_mode", custom_query_mode)
builder.add_node("counter_recon_mode", counter_recon)
builder.add_node("call_llm", call_llm)
builder.add_node("generate_elastic_query", generate_elastic_query)
builder.add_node("execute_elastic_query_C", execute_elastic_query)
builder.add_node("execute_elastic_query_S", execute_elastic_query)
builder.add_node("query_analyzer_C", query_analyzer)
builder.add_node("query_analyzer_S", query_analyzer)
builder.add_node("wait_alerts", wait_alerts)

# Add Edges
builder.add_edge(START, "assistant")

# Router Logic
builder.add_conditional_edges(
    "assistant",
    route_mechanism,
    {
        "chat_mode": "chat_mode",
        "standby_mode": "standby_mode",
        "custom_query_mode": "custom_query_mode",
        "counter_recon_mode": "counter_recon_mode",
        END : END
    }
)

# 1. Chat Flow (One-Shot: Return to Assistant)
builder.add_edge("chat_mode", "call_llm")
builder.add_edge("call_llm", "assistant")

# 2. Query Flow (One-Shot: Return to Assistant)
builder.add_edge("custom_query_mode", "generate_elastic_query")
builder.add_edge("generate_elastic_query", "execute_elastic_query_C")
builder.add_edge("execute_elastic_query_C", "query_analyzer_C")
builder.add_edge("query_analyzer_C", "assistant")

# 3. Standby Flow (Wait -> Alert -> Analyze -> Return to Assistant)
builder.add_edge("standby_mode", "wait_alerts")
builder.add_edge("wait_alerts", "execute_elastic_query_S")
builder.add_edge("execute_elastic_query_S", "query_analyzer_S")
builder.add_edge("query_analyzer_S", "assistant")

# 4. New Tool Flows (One-Shot: Return to Assistant)
builder.add_edge("counter_recon_mode", "assistant")

graph = builder.compile()
