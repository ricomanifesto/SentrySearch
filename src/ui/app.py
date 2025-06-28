"""
🔍 SentrySearch - Threat Intelligence Profile Generator
"""
import gradio as gr
from core.threat_intel_tool import ThreatIntelTool
from core.markdown_generator import generate_markdown


def generate_threat_profile(api_key, tool_name, enable_quality_control, progress=gr.Progress()):
    """Generate threat intelligence profile using original implementation"""
    if not api_key.strip():
        return "❌ Please enter your Anthropic API key", None
    
    if not tool_name.strip():
        return "❌ Please enter a tool name", None
    
    try:
        # Initialize the threat intelligence tool with the API key
        tool = ThreatIntelTool(api_key)
        tool.enable_quality_control = enable_quality_control
        
        # Generate threat intelligence
        progress(0.1, "🔄 Initializing threat intelligence generation...")
        threat_data = tool.get_threat_intelligence(
            tool_name,
            progress_callback=lambda p, msg: progress(p, msg)
        )
        
        # Generate markdown
        progress(0.98, "📝 Generating markdown report...")
        markdown_content = generate_markdown(threat_data)
        
        # Extract quality assessment for display
        quality_data = None
        if '_quality_assessment' in threat_data:
            quality_data = threat_data['_quality_assessment']
        
        progress(1.0, "✅ Threat intelligence profile generated successfully!")
        
        return markdown_content, quality_data
        
    except Exception as e:
        error_msg = f"Error generating profile: {str(e)}"
        progress(1.0, f"❌ {error_msg}")
        return error_msg, None


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
            <p style='color: #e0e0e0; margin: 10px 0 0 0;'>Comprehensive threat analysis and intelligence gathering with quality validation</p>
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
                    
                    # NEW: Quality control toggle
                    enable_quality = gr.Checkbox(
                        label="Enable Quality Control Validation",
                        value=True,
                        info="Use LLM-as-a-Judge to validate and improve content quality"
                    )
                    
                    with gr.Row():
                        generate_btn = gr.Button("🚀 Generate Profile", variant="primary", size="lg")
                        clear_btn = gr.Button("🗑️ Clear", variant="secondary")
            
        
        # Results section
        with gr.Row():
            with gr.Column():
                with gr.Tab("📄 Threat Intelligence Report"):
                    markdown_output = gr.Markdown(
                        value="Enter your API key and tool name, then click **Generate Profile** to create a threat intelligence report.",
                        height=600
                    )
                
                # NEW: Quality Assessment Tab
                with gr.Tab("📊 Quality Assessment"):
                    quality_output = gr.JSON(
                        label="Quality Validation Results",
                        value=None,
                        height=600
                    )
        
        # Event handlers
        generate_btn.click(
            fn=generate_threat_profile,
            inputs=[api_key_input, tool_input, enable_quality],
            outputs=[markdown_output, quality_output],
            show_progress=True
        )
        
        # Clear functionality
        def clear_all():
            return "", "", True, None, None
        
        clear_btn.click(
            fn=clear_all,
            outputs=[api_key_input, tool_input, enable_quality, markdown_output, quality_output]
        )
    
    interface.launch(
        server_name="0.0.0.0",
        server_port=7861,
        share=False,
        show_error=True,
        show_api=False
    )


if __name__ == "__main__":
    create_ui()