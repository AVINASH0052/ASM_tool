from utils.nvidia_llm import NvidiaLLM
import logging

# AI-powered risk analysis using NVIDIA LLM
# Generates risk scores and recommendations
class AIAnalyzer:
    def __init__(self):
        self.llm = NvidiaLLM()

    def analyze_risk(self, findings):
        """Convert scan data to risk assessment using AI"""
        try:
            return self.llm.generate_risk_analysis(findings)
        except Exception as e:
            logging.error(f"AI analysis failed: {str(e)}")
            return {
                "risk_score": 0,
                "summary": "Risk analysis unavailable",
                "recommendations": []
            }