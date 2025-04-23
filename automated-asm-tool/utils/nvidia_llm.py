import json
import logging
from openai import OpenAI
from .helpers import load_config, validate_config

class NvidiaLLM:
    def __init__(self):
        config = load_config()
        validate_config(config)
        
        self.client = OpenAI(
            base_url=config['nvidia']['base_url'],
            api_key=config['nvidia']['api_key']
        )
    
    def generate_risk_analysis(self, findings):
        """Directly implement the analysis logic here without separate query method"""
        prompt = f"""Analyze these security findings and provide:
        - Risk score (0-100)
        - Brief summary of key risks
        - Top 3 recommendations
        
        Findings: {json.dumps(findings, indent=2)}
        
        Respond in strict JSON format:
        {{
            "risk_score": int,
            "summary": str,
            "recommendations": [str]
        }}"""
        
        try:
            response = self.client.chat.completions.create(
                model="nvidia/llama-3.1-nemotron-ultra-253b-v1",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                response_format={"type": "json_object"}
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            logging.error(f"LLM query failed: {str(e)}")
            return {
                "risk_score": 0,
                "summary": "Analysis failed",
                "recommendations": []
            }