import os
import traceback
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:5173/v1",
    api_key="freellmapi-8005643a82895410602cdb9dc29f5c55f05e9192bc22a816" # Keep your working key here
)

# 1. Read your prompt requirements
with open("prompt.txt", "r", encoding="utf-8") as f:
    prompt_content = f.read()

# 2. Read the cut-off code generated so far
with open("dns_exfil_detector.py", "r", encoding="utf-8") as f:
    existing_code = f.read()

system_instruction = (
    "You are an expert Cybersecurity Engineer and Network Forensics Analyst. "
    "The provided code was cut off mid-sentence at the end of the file. "
    "Your job is to read the existing code, understand the full prompt requirements, "
    "and provide ONLY the remaining functional code needed to complete the script safely. "
    "Do not rewrite the existing code. Start exactly where it cuts off."
)

print("🔄 Sending continuation request to finish line 246+...")

try:
    response = client.chat.completions.create(
        model="auto", 
        messages=[
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": f"Original Project Requirements:\n{prompt_content}\n\nExisting Cut-Off Code:\n{existing_code}"}
        ],
        temperature=0.1
    )
    
    # Extract the continuation code text safely
    if hasattr(response, 'choices') and len(response.choices) > 0:
        first_choice = response.choices[0]
        if hasattr(first_choice, 'message') and hasattr(first_choice.message, 'content'):
            continuation_code = first_choice.message.content
        elif isinstance(first_choice, dict) and 'message' in first_choice:
            continuation_code = first_choice['message'].get('content', '')
        else:
            continuation_code = getattr(first_choice, 'text', str(first_choice))
    elif isinstance(response, dict) and 'choices' in response:
        continuation_code = response['choices'][0]['message']['content']
    else:
        continuation_code = str(response)

    # 3. Clean markdown wrapper if the model added it
    if continuation_code.startswith("```python"):
        continuation_code = continuation_code.replace("```python", "", 1)
    if continuation_code.endswith("```"):
        continuation_code = continuation_code[:-3]

    # 4. Append the new code to the existing file
    with open("dns_exfil_detector.py", "a", encoding="utf-8") as out_file:
        out_file.write("\n" + continuation_code.strip())
        
    print("██████████████████████████████████████████████████")
    print("✅ Success! The missing code has been appended to 'dns_exfil_detector.py'.")
    print("██████████████████████████████████████████████████")

except Exception as e:
    print(f"❌ Continuation failed: {str(e)}")
    traceback.print_exc()
