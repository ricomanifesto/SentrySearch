"""
🔍 SentrySearch - Threat Intelligence Profile Generator
"""
import os
import gradio as gr
from datetime import datetime
import tempfile
import json

def generate_threat_profile(api_key, tool_name):
    """Generate threat intelligence profile"""
    if not api_key.strip():
        return "❌ Please enter your Anthropic API key"
    
    if not tool_name.strip():
        return "❌ Please enter a tool name"
    
    try:
        # Import here to avoid any module-level issues
        from threat_intel_tool import ThreatIntelTool
        from markdown_generator import generate_markdown
        
        # Initialize the tool with the API key
        tool = ThreatIntelTool(api_key)
        
        # Generate threat intelligence
        threat_data = tool.get_threat_intelligence(tool_name)
        
        # Generate markdown
        markdown_content = generate_markdown(threat_data)
        
        return markdown_content
        
    except Exception as e:
        return f"❌ Error generating profile: {str(e)}"

# Create the interface using gr.Interface (which works)
interface = gr.Interface(
    fn=generate_threat_profile,
    inputs=[
        gr.Textbox(label="🔑 Anthropic API Key", placeholder="Enter your API key (sk-ant-...)", type="password"),
        gr.Textbox(label="🎯 Tool/Threat Name", placeholder="e.g., 'Cobalt Strike', 'ShadowPad'")
    ],
    outputs=gr.Markdown(label="📊 Threat Intelligence Report"),
    title="🔍 SentrySearch: AI-Powered Threat Intelligence",
    description="Generate comprehensive threat intelligence reports using Claude AI. Enter your Anthropic API key and the name of a tool/threat to analyze.",
    examples=[
        ["", "Cobalt Strike"],
        ["", "ShadowPad"],
        ["", "Mimikatz"]
    ]
)

if __name__ == "__main__":
    interface.launch()