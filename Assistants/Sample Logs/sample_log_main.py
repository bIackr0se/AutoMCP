# main.py
import asyncio
import json
import aiohttp
from datetime import datetime, timedelta

# Import the necessary functions and model from your sample_log_new.py file
from sample_log_assistant import query_log_data, QueryLogDataParams

# LLM Interaction Functions

async def get_tool_parameters_from_llm(user_question: str) -> dict:
    """
    Asks the LLM to act as a router. It analyzes the user's question and
    extracts the correct parameters for the query_log_data tool.
    """
    tool_schema = QueryLogDataParams.model_json_schema()

    # LLM is so dumb that we can manually calculate phrases like 'today' and 'yesterdaay'
    today_str = datetime.now().strftime("%Y-%m-%d")
    yesterday_str = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")

    prompt = f"""
    You are an expert at extracting structured information. Analyze the user's question
    and generate a JSON object with parameters for the `query_log_data` tool.

    Tool Parameters Schema:
    {json.dumps(tool_schema, indent=2)}

    Current date is {today_str}.
    If the user asks for "last week", "yesterday", etc., calculate the dates.
    If a parameter is not mentioned, omit it from the JSON.
    If the question cannot be answered using the tool (e.g., general knowledge),
    return an empty JSON object: {{}}.

    User Question: "{user_question}"

    Respond ONLY with the JSON object.
    """
    
    payload = {"model": "llama3:8b", "prompt": prompt, "stream": False, "format": "json"}
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post("http://localhost:11434/api/generate", json=payload) as resp:
                resp.raise_for_status()
                ollama_response_str = await resp.text()
                ollama_response_obj = json.loads(ollama_response_str)
                params_str = ollama_response_obj.get('response', '{}')
                params_dict = json.loads(params_str)
                return params_dict
        except Exception as e:
            print(f"Error getting parameters from LLM: {e}")
            return {}

async def get_final_answer_from_llm(context: dict, question: str) -> str:
    """
    Generates a final, human-readable answer based on the provided context and question.
    """
    prompt = f"""
    You are a data analyst assistant. Answer the user's question based ONLY on the
    following context.

    --- CONTEXT ---
    {json.dumps(context, indent=2)}

    --- QUESTION ---
    {question}

    --- ANSWER ---
    """
    payload = {"model": "llama3:8b", "prompt": prompt, "stream": False}
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post("http://localhost:11434/api/generate", json=payload) as resp:
                resp.raise_for_status()
                response_text = await resp.text()
                data = json.loads(response_text)
                return data.get('response', 'Could not get a valid response.').strip()
        except Exception as e:
            return f"An error occurred while getting the final answer: {e}"

# Main Execution Flow

async def main():
    """Main loop to run the assistant."""
    print("Log Data Assistant is ready. Type 'exit' to quit.")
    while True:
        user_question = input("\n> ")
        if user_question.lower() == 'exit':
            break

        # Extract Parameters
        print("\n[STEP 1] Extracting tool parameters from user question...")
        tool_params_dict = await get_tool_parameters_from_llm(user_question)

        if not tool_params_dict:
            print("--> No tool required. Forwarding question directly to LLM.")
            final_answer = await get_final_answer_from_llm({"info": "No tool was called."}, user_question)
        else:
            try:
                print(f"--> Parameters received from LLM: {tool_params_dict}")
                
                # Validate and convert parameters using the Pydantic model
                params = QueryLogDataParams(**tool_params_dict)
                
                # Execute the Data Tool
                print("\n[STEP 2] Executing the data tool (query_log_data)...")
                result_json_str = await query_log_data(params)
                retrieved_context = json.loads(result_json_str)

                print("\n--- RAW DATA RETURNED FROM TOOL ---")
                print(json.dumps(retrieved_context, indent=2))
                print("-----------------------------------\n")


                # STEP 3: Generate Final Answer 
                print("[STEP 3] Sending data to LLM for interpretation...")
                
                print("\n--- CONTEXT SENT FOR INTERPRETATION ---")
                print(json.dumps(retrieved_context, indent=2))
                print("---------------------------------------\n")

                final_answer = await get_final_answer_from_llm(retrieved_context, user_question)

            except Exception as e:
                final_answer = f"An error occurred during tool execution: {e}"

        # FINAL RESULT
        print("\n--- Assistant's Answer ---")
        print(final_answer)

if __name__ == "__main__":
    asyncio.run(main())