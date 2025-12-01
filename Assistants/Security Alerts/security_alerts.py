"""
MCP Server for querying and summarizing Elastic Security alerts
stored in Elasticsearch.
"""
import os
from typing import Any, Optional
import json
from datetime import datetime
from pydantic import BaseModel, field_validator
from mcp.server.fastmcp import FastMCP
from elasticsearch import AsyncElasticsearch
from contextlib import asynccontextmanager

# Initialize FastMCP server
mcp = FastMCP("security-alert-server")

ES_HOST = "http://localhost:9200"
ES_INDEX = ".alerts-security.alerts-default"
from dotenv import load_dotenv
load_dotenv()
ES_API_KEY = os.getenv("ES_API_KEY")

class QueryAlertDataParams(BaseModel):
    # Parameters for filtering security alerts
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    rule_name: Optional[str] = None     # e.g., "Potential Internal Linux SSH Brute Force Detected"
    source_ip: Optional[str] = None     # e.g., "192.168.0.180"
    host_name: Optional[str] = None     # e.g., "ercodex"
    event_outcome: Optional[str] = None # e.g., "failure", "success"

    sort_by: Optional[str] = "@timestamp" # Sort by time by default
    sort_order: Optional[str] = "desc"    # In descending order by default
    limit: Optional[int] = 5              # Get back 5 results by default

    @field_validator('*', mode='before')
    def empty_str_to_none(cls, v):
        if v == "": return None
        return v

    @field_validator('start_date', 'end_date')
    def validate_date_format(cls, value):
        if value is None: return value
        try:
            datetime.fromisoformat(value)
            return value
        except ValueError:
            raise ValueError(f"Invalid date format: '{value}'.")

@asynccontextmanager
async def get_es_client():
    client = AsyncElasticsearch([ES_HOST], api_key=ES_API_KEY)
    try:
        yield client
    finally:
        await client.close()

async def query_elasticsearch(query: dict) -> dict[str, Any] | None:
    print(f"--> [ES Query]: {json.dumps(query)}")
    async with get_es_client() as client:
        try:
            response = await client.search(index=ES_INDEX, body=query)
            return response
        except Exception as e:
            print(f"Error querying Elasticsearch: {e}")
            return None

@mcp.tool()
async def query_alert_data(params: QueryAlertDataParams) -> str:
    """
    Queries security alert data with customizable filters.
    """
    query = {"query": {"bool": {"must": []}}}
    filters = query["query"]["bool"]["must"]

    # Date filter logic
    if params.start_date or params.end_date:
        date_range = {}
        # Handle single-day queries to span the full 24 hours
        if params.start_date and params.start_date == params.end_date and "T" not in params.start_date:
            date_range["gte"] = params.start_date
            date_range["lte"] = f"{params.end_date}||/d"
        else:
            if params.start_date: date_range["gte"] = params.start_date
            if params.end_date: date_range["lte"] = params.end_date
        
        filters.append({"range": {"@timestamp": date_range}})

    # Filter by rule name (using 'match' for flexibility)
    if params.rule_name:
        filters.append({"match": {"kibana.alert.rule.name": params.rule_name}})
        
    # Filter by source IP
    if params.source_ip:
        filters.append({"term": {"source.ip": params.source_ip}})

    # Filter by host name
    if params.host_name:
        filters.append({"term": {"host.name": params.host_name}})
        
    # Filter by event outcome
    if params.event_outcome:
        filters.append({"term": {"event.outcome": params.event_outcome}})
    
    if not filters:
        query["query"] = {"match_all": {}}

    query["sort"] = [{"@timestamp": "desc"}]
    query["size"] = 5

    query["fields"] = [
        "@timestamp",
        "kibana.alert.rule.name",
        "kibana.alert.severity",
        "event.outcome",
        "source.ip",
        "host.name",
        "host.ip",
        "kibana.alert.reason"
    ]
    query["_source"] = False
    
    data = await query_elasticsearch(query)
    if not data:
        return json.dumps({"error": "Unable to query Elasticsearch"}, indent=2)
    
    structured_response = {
        "query_parameters": params.model_dump(exclude_none=True),
        "data": dict(data)
    }
    return json.dumps(structured_response, indent=2)

if __name__ == "__main__":
    mcp.run()