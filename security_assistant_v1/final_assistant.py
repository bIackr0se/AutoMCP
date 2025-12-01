""" 
Ultimate MCP Server that can reach out to multiple data sources to make 
correlations between them and give explanatory, human-language results.

Author: Eren Cil
"""

# +++++++++++++++++++++ Libraries +++++++++++++++++++++
import os
from typing import Any, Optional
import json
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, field_validator
from mcp.server.fastmcp import FastMCP
from elasticsearch import AsyncElasticsearch
from contextlib import asynccontextmanager
from dotenv import load_dotenv
# +++++++++++++++++++++++++++++++++++++++++++++++++++++


mcp = FastMCP("ultimate-assistant-server") # Initialize MCP server


# +++++++++++++++++++++ Constants +++++++++++++++++++++
load_dotenv()
ES_HOST = "http://localhost:9200"
ES_ALERTS_INDEX = ".internal.alerts-security.alerts-default*" # Index for security alerts
ES_INTEL_INDEX = "otx_pulses_minimal" # Index for threat intelligence
ES_API_KEY = os.getenv("ES_API_KEY")
LOCAL_TIMEZONE = 1
LOCAL_TZINFO = timezone(timedelta(hours=LOCAL_TIMEZONE)) # For correcting local time to UTC


# +++++++++++++++++++++ Pydantic Class +++++++++++++++++++++ 
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


# ++++++++++++++++++++ Initialize Client +++++++++++++++++++
@asynccontextmanager
async def es_client():
    client = AsyncElasticsearch([ES_HOST], api_key=ES_API_KEY)
    try:
        yield client
    finally:
        await client.close()

# Query function
async def query_es(query: dict, index: str = ES_ALERTS_INDEX ) -> dict[str, Any] | None:

    # Print the query for DEBUG reasons
    print(f"ES QUERY on {index}: {json.dumps(query)}")
    async with es_client() as client:
        try:
            response = await client.search(index=index, body=query)
            return response
        except Exception as e:
            print(f"Error querying Elasticsearch: {e}")
            return None

# +++++++++++++++++++++ Resources +++++++++++++++++++++
# Get types of severity in a list (Doesn't do anything now)
@mcp.resource("alerts://security_alerts/severity_types")
async def list_severity_types() -> str:
    query = {
        "size": 0,
        "aggs": {"severity_types": {"terms": {"field": "kibana.alert.severity", "size": 4}}}
    }
    data = await query_es(query)
    if not data: return json.dumps({"error": "Query failed"}, indent=2)
    buckets = data.get("aggregations", {}).get("severity_types", {}).get("buckets", [])
    os_types = [bucket["key"] for bucket in buckets]
    return json.dumps({"available_severity_types": os_types}, indent=2)

# +++++++++++++++++++++ Tools +++++++++++++++++++++
# For querying each field and making aggregations
@mcp.tool()
async def query_alerts(params: QueryAlertParams) -> str:
    
    DESIRED_OUTPUT_FIELDS = [
        "kibana.alert.rule.execution.timestamp",
        "kibana.alert.rule.parameters.severity",    # Pydantic 'severity'
        "kibana.alert.rule.name",                   # Pydantic 'rule_name'
        "kibana.alert.rule.parameters.description", # Pydantic 'description'
        "kibana.alert.rule.parameters.threat",      # MITRE Attack Information
        "host.ip"                                   # Host IP 
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
        filters.append({"terms": {"kibana.alert.rule.parameters.severity": params.severity}})
    
    # Rule name
    if params.rule_name:
        filters.append({"match": {"kibana.alert.rule.name": params.rule_name}})

    if params.host_ip:
        filters.append({"match": {"host.ip": params.host_ip}})

    if params.mitre_attack_info:
        filters.append({
            "terms": {
                "kibana.alert.rule.parameters.threat" : params.mitre_attack_info
            }
        })

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
        query["size"] = 15

        query["_source"] = DESIRED_OUTPUT_FIELDS

    # Run the query
    data = await query_es(query)
    if not data:
        return json.dumps({"error": "Unable to query Elasticsearch"}, indent=2)
    
    processed_data = {}

    if params.aggregation:
        processed_data['aggregations'] = data.get('aggregations', {})
        processed_data['total_hits'] = data.get('hits', {}).get('total', {}).get('value', 0)
    
    else:
        hits = data.get('hits', {}).get('hits', [])
        
        clean_alerts = [hit.get('_source') for hit in hits if hit.get('_source')]
        
        processed_data['total_hits_found'] = data.get('hits', {}).get('total', {}).get('value', 0)
        processed_data['hits_returned'] = len(clean_alerts)
        processed_data['alerts'] = clean_alerts

    structured_response = {
        "query_parameters": params.model_dump(exclude_none=True),
        "data": processed_data 
    }
    
    return json.dumps(structured_response, indent=2, default=str)
# +++++++++++++++++++++ Main +++++++++++++++++++++ 
if __name__ == "__main__":
    mcp.run()