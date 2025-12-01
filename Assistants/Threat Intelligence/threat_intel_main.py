# Import libraries
import asyncio
import json
import aiohttp
from datetime import datetime
from pydantic import ValidationError

# Import from MCP server file
from threat_intel import query_threat_data, QueryThreatDataParams

async def get_tool_parameters_from_llm(user_question: str) -> dict:
    # Define the tool and build up the prompt

    tool_schema = QueryThreatDataParams.model_json_schema()

    today_str = datetime.now().strftime("%Y-%m-%d")

    prompt = f"""
        You are an expert at extracting structured information from a user's question to call a tool.

        Respond with a JSON object containing parameters for the tool call.
        
        Tool Parameters Schema:
        {json.dumps(tool_schema, indent=2)}

        Current date is {today_str}. If user has some keywords like 'yesterday, last week, etc.' in his question, calculate this dates correctly.

        IMPORTANT: IF a parameter is not mentioned, DO NOT INCLUDE its key in the JSON.
        If the question cannot be answered using the tool, return an empty JSON object: {{}}.

        --- CRITICAL INSTRUCTION ---
        The response MUST be a FLAT JSON object that ONLY contains the VALUE of the parameters.
        DO NOT include schema keywords like 'type', 'title', 'anyOf', or 'default' in the final JSON output.
        Example of desired output: {{"pulse_description": "BlueNoroff", "start_date": "2025-01-01"}}
        Example of WRONG output: {{"pulse_description": {{"type": "string", "default": "BlueNoroff"}}}}
        ---
        
        User Question: '{user_question}'
        Respond ONLY with the JSON object. 
    """

    # Define the payload
    payload = {"model": "llama3:8b", "prompt": prompt, "stream": False, "format": "json"}

    # Start session
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post("http://localhost:11434/api/generate", json= payload) as resp:
                resp.raise_for_status()

                # Get the Ollama response
                ollama_response_str = await resp.text()

                # Turn the Ollama response into an object with 'loads'
                ollama_response_obj = json.loads(ollama_response_str)

                params_str = ollama_response_obj.get('response', '{}')

                return json.loads(params_str)
            
        except Exception as e:
            print(f"Error getting parameters from LLM: {type(e).__name__} - {e} ")
            print("Returning empty dictionary.")
            return {}
# ----- end-Get-Tool-Parameters-From-LLM -----


def format_context_as_report(context: dict) -> str:
    # Document chunking. Transform the raw JSON from Elasticsearch into a readable report for the LLM

    # No data found
    if "data" not in context or "hits" not in context["data"]["hits"]:
        return "No data found for the given criteria."
    
    # Take hits
    hits = context["data"]["hits"]["hits"]
    if not hits: # Hits is empty
        return "No threat intelligence pulses matched the query."
    
    # Build the report
    report = "--- Threat Intelligence Summary ---\n"
    report += f"Found {len(hits)} relevant threat reports.\n" # Show the number of hits

    for i, hit in enumerate(hits):
        source = hit.get("_source", {})
        report += f"\n--- Report #{i+1} ---\n"
        report += f"Threat Name: {source.get('name', 'N/A')}\n"
        report += f"Description: {source.get('description', 'N/A')}\n"
        report += f"Author: {source.get('author_name', 'N/A')}\n"
        report += f"Tags: {', '.join(source.get('tags', []))}\n"
        
        indicators = source.get('indicators', [])
        if indicators:
            report += "Associated Indicators:\n"
            # Loop through each indicator and print all its details.
            for ind in indicators:
                report += f"  - Indicator: {ind.get('indicator', 'N/A')}\n"
                report += f"    - Type: {ind.get('type', 'N/A')}\n"
                # Only show fields if they have a value, for a cleaner report.
                if ind.get('title'):
                    report += f"    - Title: {ind.get('title')}\n"
                if ind.get('description'):
                    report += f"    - Description: {ind.get('description')}\n"
                if ind.get('role'):
                    report += f"    - Role: {ind.get('role')}\n"
                if ind.get('is_active') is not None:
                    report += f"    - Is Active: {ind.get('is_active')}\n"
    
    return report
# ----- end-Format-Context-As-Report -----


async def get_final_answer_from_llm(context_report: str, question: str):
    # Generates the final answer based on the formatted text report.
    
    prompt = f"""
    You are a cybersecurity analyst. Answer the user's question based on the following
    threat intelligence summary. Make sure the data is correct.

    --- THREAT INTELLIGENCE SUMMARY ---
    {context_report}

    --- QUESTION ---
    {question}

    --- ANALYSIS & ANSWER ---
    """

    payload = {"model": "llama3:8b", "prompt": prompt, "stream": True}
    print("\n--- Assistant ---")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post("http://localhost:11434/api/generate", json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.content:
                    if line:
                        chunk = json.loads(line.decode('utf-8'))
                        token = chunk.get('response', '')
                        print(token, end="", flush=True)
                        if chunk.get('done'):
                            print()
        except Exception as e:
            print(f"\nAn error occurred while getting the final answer: {e}")
# ----- end-Get-Final-Answer-From-LLM -----

async def main():
    print("Threat Intelligence Assistant is ready. Type 'exit' to quit.")
    while True:
        user_question = input("\n> ")
        if user_question.lower() == "exit":
            break

        print("\n[Step 1: Figuring out parameters from your question...]")
        tool_params_dict = await get_tool_parameters_from_llm(user_question)

        if not tool_params_dict:
            print("--> Could not determine parameters. Please ask a question about threat intelligence.")
            continue

        try:
            print(f"--> LLM generated parameters: {json.dumps(tool_params_dict, indent=2)}")

            try:
                params = QueryThreatDataParams(**tool_params_dict)
            except ValidationError as e:
                print(f"Pydantic Validation Error: {e}")
                print(f"LLM geçersiz parametreler üretti. Lütfen sorunuzu farklı sorun.")
                continue

            
            print("\n[Step 2: Querying threat intelligence data...]")
            result_json_str = await query_threat_data(params)
            retrieved_context = json.loads(result_json_str)
            
            print("\n[Step 3: Formatting data into a report for the final LLM...]")

            report_context = format_context_as_report(retrieved_context)
            print("Printing the report for checking...")
            print(report_context)

            print("\n[Step 4: Generating final analysis...]")
            await get_final_answer_from_llm(report_context, user_question)
        except Exception as e:
            print(f"\n--- Assistant ---\nAn error occurred: {e}")

if __name__ == "__main__":
    asyncio.run(main())