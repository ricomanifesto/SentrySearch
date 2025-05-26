"""
🔍 SentrySearch - Threat Intelligence Profile Generator
"""
import os
import gradio as gr
from datetime import datetime
from threat_intel_tool import ThreatIntelTool
from markdown_generator import generate_markdown
import json
import tempfile


def generate_threat_profile(api_key, tool_name, progress=gr.Progress()):
    """Generate threat intelligence profile with progress tracking"""
    if not api_key.strip():
        return "❌ Please enter your Anthropic API key", None, None
    
    if not tool_name.strip():
        return "❌ Please enter a tool name", None, None
    
    try:
        # Initialize the tool with the API key
        tool = ThreatIntelTool(api_key)
        
        # Generate threat intelligence
        progress(0.1, "🔄 Initializing threat intelligence generation...")
        threat_data = tool.get_threat_intelligence(
            tool_name,
            progress_callback=lambda p, msg: progress(p, msg)
        )
        
        # Generate markdown
        progress(0.95, "📝 Generating markdown report...")
        markdown_content = generate_markdown(threat_data)
        
        # Create temporary file for markdown download
        temp_dir = tempfile.gettempdir()
        md_filename = f"threat_intel_{tool_name.replace(' ', '_').lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        md_filepath = os.path.join(temp_dir, md_filename)
        
        # Write markdown to temporary file
        with open(md_filepath, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        progress(1.0, "✅ Threat intelligence profile generated successfully!")
        
        return None, markdown_content, md_filepath
        
    except Exception as e:
        error_msg = f"Error generating profile: {str(e)}"
        progress(1.0, f"❌ {error_msg}")
        return error_msg, None, None


def create_ui():
    """Main function to launch the application"""
    print("🚀 Starting SentrySearch - Threat Intelligence Profile Generator...")
    print("📌 Make sure you have your Anthropic API key ready!")
    print("🌐 Opening web interface...")
    
    with gr.Blocks(title="SentrySearch: AI-Powered Threat Intelligence", theme=gr.themes.Soft()) as interface:
        # Header section
        gr.HTML("""
        <div style='text-align: center; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 10px; margin-bottom: 20px;'>
            <h1 style='color: white; margin: 0; font-size: 2.5em;'>SentrySearch</h1>
            <h2 style='color: #f0f0f0; margin: 10px 0 0 0; font-weight: 300;'>AI-Powered Threat Intelligence Platform</h2>
            <p style='color: #e0e0e0; margin: 10px 0 0 0;'>Comprehensive threat analysis and intelligence gathering</p>
        </div>
        """)
        
        # Main interface layout
        with gr.Row():
            with gr.Column(scale=2):
                # Input section
                with gr.Group():
                    gr.Markdown("### 🎯 Configuration & Target Selection")
                    api_key_input = gr.Textbox(
                        label="🔑 Anthropic API Key",
                        placeholder="Enter your Anthropic API key (sk-ant-...)",
                        type="password",
                        lines=1
                    )
                    tool_input = gr.Textbox(
                        label="Tool/Threat Name",
                        placeholder="Enter the name of a tool, malware, or threat (e.g., 'Cobalt Strike', 'ShadowPad')",
                        lines=1
                    )
                    
                    with gr.Row():
                        generate_btn = gr.Button("🚀 Generate Profile", variant="primary", size="lg")
                        clear_btn = gr.Button("🗑️ Clear", variant="secondary")
            
            with gr.Column(scale=1):
                # Status and download section
                with gr.Group():
                    gr.Markdown("### 📊 Status & Export")
                    error_output = gr.Textbox(
                        label="Status",
                        interactive=False,
                        visible=False
                    )
                    download_file = gr.File(
                        label="📥 Download Markdown Report",
                        interactive=False,
                        visible=True
                    )
        
        # Results section
        with gr.Row():
            with gr.Column():
                # Single markdown view (no tabs)
                markdown_output = gr.Markdown(
                    value="Enter your API key and tool name, then click **Generate Profile** to create a threat intelligence report.",
                    height=600
                )
        
        # Event handlers
        generate_btn.click(
            fn=generate_threat_profile,
            inputs=[api_key_input, tool_input],
            outputs=[error_output, markdown_output, download_file],
            show_progress=True
        )
        
        # Clear functionality
        def clear_all():
            return "", "", None, None
        
        clear_btn.click(
            fn=clear_all,
            outputs=[api_key_input, tool_input, markdown_output, download_file]
        )
    
    interface.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        show_error=True,
        show_api=False  # This removes the "Use via API" link
    )


if __name__ == "__main__":
    create_ui()