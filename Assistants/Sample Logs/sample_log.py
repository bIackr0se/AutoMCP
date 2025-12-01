"""
An MCP server for getting human-language responses for Kibana Sample Log data.
"""

# +++++++++++++++++++++ Libraries +++++++++++++++++++++ 
import os
from typing import Any, Optional
import json
from datetime import datetime
from pydantic import BaseModel, field_validator
from mcp.server.fastmcp import FastMCP
from elasticsearch import AsyncElasticsearch
from contextlib import asynccontextmanager

mcp = FastMCP("kibana-log-server") # Initialize the MCP server

# +++++++++++++++++++++ Constants +++++++++++++++++++++ 
import os
from dotenv import load_dotenv
load_dotenv()
ES_HOST = "http://localhost:9200"
ES_INDEX = "kibana_sample_data_logs"
ES_API_KEY = os.getenv("ES_API_KEY")

# +++++++++++++++++++++ Pydantic Class +++++++++++++++++++++ 
class QueryLogDataParams(BaseModel):

    # Selected fields
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    aggregation: Optional[str] = None
    machine_os: Optional[str] = None
    response_code: Optional[int] = None
    tags: Optional[str] = None
    url: Optional[str] = None

    # Fill empty spaces with 'None'.
    @field_validator('*', mode='before')
    def empty_str_to_none(cls, v):
        if v == "": return None
        return v

    # Check the date format and transform it into ISO format.
    @field_validator('start_date', 'end_date')
    def validate_date_format(cls, value):
        if value is None: return value
        try:
            datetime.fromisoformat(value)
            return value
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

# Initialize client.
@asynccontextmanager
async def get_es_client():
    client = AsyncElasticsearch([ES_HOST], api_key=ES_API_KEY)
    try:
        yield client
    finally:
        await client.close()

async def query_elasticsearch(query: dict) -> dict[str, Any] | None:
    
    # Print the query
    print(f"--> [ES Query]: {json.dumps(query)}")
    async with get_es_client() as client:
        try:
            response = await client.search(index=ES_INDEX, body=query)
            return response
        except Exception as e:
            print(f"Error querying Elasticsearch: {e}")
            return None

# +++++++++++++++++++++ Resources +++++++++++++++++++++ 

# Get the operating system types
@mcp.resource("logs://kibana_sample/os_types")
async def list_os_types() -> str:
    query = {
        "size": 0,
        "aggs": { "operating_systems": { "terms": { "field": "machine.os.keyword", "size": 20 } } }
    }
    data = await query_elasticsearch(query)
    if not data: return json.dumps({"error": "Query failed"}, indent=2)
    buckets = data.get("aggregations", {}).get("operating_systems", {}).get("buckets", [])
    os_types = [bucket["key"] for bucket in buckets]
    return json.dumps({"available_os_types": os_types}, indent=2)

# Get the 'latest' logs
@mcp.resource("logs://kibana_sample/latest")
async def get_latest_logs() -> str:
    query = { "query": {"match_all": {}}, "sort": [{"@timestamp": "desc"}], "size": 10 }
    data = await query_elasticsearch(query)
    if not data: return json.dumps({"error": "Query failed"}, indent=2)
    return json.dumps(data.get("hits", {}).get("hits", []), indent=2)

# +++++++++++++++++++++ Tools +++++++++++++++++++++

# For querying each field and making aggregations
@mcp.tool()
async def query_log_data(params: QueryLogDataParams) -> str:
    query = {"query": {"bool": {"must": []}}}
    filters = query["query"]["bool"]["must"]

    if params.start_date or params.end_date:
        date_range = {}
        if params.start_date: date_range["gte"] = params.start_date
        if params.end_date: date_range["lte"] = params.end_date
        filters.append({"range": {"@timestamp": date_range}})

    if params.machine_os:
        filters.append({"term": {"machine.os.keyword": params.machine_os}})

    if params.response_code:
        filters.append({"term": {"response": params.response_code}})

    if params.tags:
        filters.append({"term": {"tags.keyword": params.tags}})

    if params.url:
        filters.append({"match": {"url.original": params.url}})
    
    if not filters:
        query["query"] = {"match_all": {}}

    if params.aggregation:
        interval_mapping = {"hourly": "1h", "daily": "1d", "weekly": "1w", "monthly": "1M"}
        es_interval = interval_mapping.get(params.aggregation, "1d")
        query["aggs"] = {
            "time_series": {
                "date_histogram": {"field": "@timestamp", "calendar_interval": es_interval, "min_doc_count": 1},
                "aggs": {"total_bytes": {"sum": {"field": "bytes"}}, "avg_bytes": {"avg": {"field": "bytes"}}}
            }
        }
        query["size"] = 0
    else:
        query["sort"] = [{"@timestamp": "desc"}]
        query["size"] = 25

    data = await query_elasticsearch(query)
    if not data:
        return json.dumps({"error": "Unable to query Elasticsearch"}, indent=2)
    
    structured_response = {
        "query_parameters": params.model_dump(exclude_none=True),
        "data": dict(data)
    }
    return json.dumps(structured_response, indent=2)

# +++++++++++++++++++++ Main +++++++++++++++++++++ 
if __name__ == "__main__":
    mcp.run()