"""
🔍 SentrySearch - Threat Intelligence Profile Generator
"""

import gradio as gr
import os
import pandas as pd
import uuid
from datetime import datetime
from src.core.cached_threat_profile_generator import CachedThreatProfileGenerator
from src.core.markdown_generator import generate_markdown

GENERATION_ERROR_MESSAGE = "Error generating profile. Please try again."
REPORT_LOAD_ERROR_MESSAGE = "Error loading report. Please try again."

# Import cloud storage if enabled
try:
    from src.storage import report_service, create_tables, test_connection

    STORAGE_ENABLED = os.getenv("ENABLE_REPORT_STORAGE", "true").lower() == "true"
    if STORAGE_ENABLED:
        print("✅ Cloud storage enabled")
    else:
        print("⚠️ Cloud storage disabled")
except ImportError as e:
    print(f"⚠️ Cloud storage not available: {e}")
    STORAGE_ENABLED = False


def generate_threat_profile(tool_name, enable_quality_control, progress=gr.Progress()):
    """Generate a threat intelligence profile."""
    if not tool_name.strip():
        return "❌ Please enter a tool name", None

    def safe_generation_progress(value, message):
        if isinstance(message, str) and message.lstrip().startswith(("❌ Error", "Error")):
            progress(value, GENERATION_ERROR_MESSAGE)
            return
        progress(value, message)

    try:
        # Initialize the threat intelligence tool with the API key and tracing enabled
        import os

        trace_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "traces")
        os.makedirs(trace_dir, exist_ok=True)
        threat_profile_generator = CachedThreatProfileGenerator(
            enable_tracing=True, trace_export_dir=trace_dir
        )
        threat_profile_generator.enable_quality_control = enable_quality_control

        # Generate threat intelligence
        progress(0.1, "🔄 Initializing threat intelligence generation...")
        threat_data = threat_profile_generator.get_threat_intelligence(
            tool_name, progress_callback=safe_generation_progress
        )

        # Generate markdown
        progress(0.98, "📝 Generating markdown report...")
        markdown_content = generate_markdown(threat_data)

        # Extract quality assessment for display
        quality_data = None
        if "_quality_assessment" in threat_data:
            quality_data = threat_data["_quality_assessment"]

        progress(1.0, "✅ Threat intelligence profile generated successfully!")

        # Store report in cloud storage if enabled
        if STORAGE_ENABLED:
            try:
                report_data = {
                    "id": threat_data.get("id", str(uuid.uuid4())),
                    "tool_name": tool_name,
                    "category": threat_data.get("category", "unknown"),
                    "threat_type": threat_data.get("threatType", "unknown"),
                    "quality_score": quality_data.get("overall_score") if quality_data else None,
                    "processing_time_ms": threat_data.get("_processing_time_ms"),
                    "threat_data": threat_data,
                    "quality_assessment": quality_data,
                    "markdown_content": markdown_content,
                    "trace_data": threat_data.get("_trace_data"),
                    "search_tags": [tool_name.lower(), threat_data.get("category", "").lower()],
                }

                report_service.store_report(report_data)
                print(f"✅ Report stored in cloud: {report_data['id']}")
            except Exception as e:
                print(f"⚠️ Could not store report in cloud: {e}")

        return markdown_content, quality_data

    except Exception:
        error_msg = GENERATION_ERROR_MESSAGE
        progress(1.0, error_msg)
        return error_msg, None


def load_report_list():
    """Load list of reports from cloud storage"""
    if not STORAGE_ENABLED:
        return pd.DataFrame(columns=["Tool Name", "Category", "Quality Score", "Created", "ID"])

    try:
        reports = report_service.list_reports(limit=50)

        if not reports:
            return pd.DataFrame(columns=["Tool Name", "Category", "Quality Score", "Created", "ID"])

        # Convert to DataFrame for display
        df_data = []
        for report in reports:
            df_data.append(
                {
                    "Tool Name": report.get("tool_name", "Unknown"),
                    "Category": report.get("category", "Unknown"),
                    "Quality Score": (
                        f"{report.get('quality_score', 0):.2f}"
                        if report.get("quality_score")
                        else "N/A"
                    ),
                    "Created": (
                        report.get("created_at", "").split("T")[0]
                        if report.get("created_at")
                        else "Unknown"
                    ),
                    "ID": report.get("id", ""),
                }
            )

        return pd.DataFrame(df_data)

    except Exception as e:
        print(f"Error loading reports: {e}")
        return pd.DataFrame(columns=["Tool Name", "Category", "Quality Score", "Created", "ID"])


def view_report(report_id):
    """View a specific report by ID"""
    if not STORAGE_ENABLED or not report_id:
        return "Storage not enabled or no report selected", None

    try:
        report = report_service.get_report(report_id, include_content=True)

        if not report:
            return "Report not found", None

        markdown_content = report.get("markdown_content", "No content available")
        quality_data = report.get("quality_assessment")

        return markdown_content, quality_data

    except Exception:
        return REPORT_LOAD_ERROR_MESSAGE, None


def search_reports(query, category_filter):
    """Search reports with filters"""
    if not STORAGE_ENABLED:
        return pd.DataFrame(columns=["Tool Name", "Category", "Quality Score", "Created", "ID"])

    try:
        # Apply filters
        category = category_filter if category_filter != "All" else None
        search_query = query.strip() if query.strip() else None

        reports = report_service.list_reports(
            limit=50, search_query=search_query, category=category
        )

        if not reports:
            return pd.DataFrame(columns=["Tool Name", "Category", "Quality Score", "Created", "ID"])

        # Convert to DataFrame
        df_data = []
        for report in reports:
            df_data.append(
                {
                    "Tool Name": report.get("tool_name", "Unknown"),
                    "Category": report.get("category", "Unknown"),
                    "Quality Score": (
                        f"{report.get('quality_score', 0):.2f}"
                        if report.get("quality_score")
                        else "N/A"
                    ),
                    "Created": (
                        report.get("created_at", "").split("T")[0]
                        if report.get("created_at")
                        else "Unknown"
                    ),
                    "ID": report.get("id", ""),
                }
            )

        return pd.DataFrame(df_data)

    except Exception as e:
        print(f"Error searching reports: {e}")
        return pd.DataFrame(columns=["Tool Name", "Category", "Quality Score", "Created", "ID"])


def create_ui():
    """Main function to launch the application"""
    print("🚀 Starting SentrySearch - Threat Intelligence Profile Generator...")
    print("📌 Make sure OpenCode is running and configured with a model provider.")
    print("🌐 Opening web interface...")

    with gr.Blocks(
        title="SentrySearch: AI-Powered Threat Intelligence", theme=gr.themes.Soft()
    ) as interface:
        # Header section
        gr.HTML("""
        <div style='text-align: center; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 10px; margin-bottom: 20px;'>
            <h1 style='color: white; margin: 0; font-size: 2.5em;'>SentrySearch</h1>
            <h2 style='color: #f0f0f0; margin: 10px 0 0 0; font-weight: 300;'>AI-Powered Threat Intelligence Platform</h2>
            <p style='color: #e0e0e0; margin: 10px 0 0 0;'>Comprehensive threat analysis and intelligence gathering with quality validation</p>
        </div>
        """)

        # Main interface layout using tabs
        with gr.Tabs():
            # Tab 1: Generate New Report
            with gr.Tab("🚀 Generate Report"):
                with gr.Row():
                    with gr.Column(scale=2):
                        # Input section
                        with gr.Group():
                            gr.Markdown("### 🎯 Configuration & Target Selection")
                            tool_input = gr.Textbox(
                                label="Tool/Threat Name",
                                placeholder="Enter the name of a tool, malware, or threat (e.g., 'Cobalt Strike', 'ShadowPad')",
                                lines=1,
                            )

                            # Quality control toggle
                            enable_quality = gr.Checkbox(
                                label="Enable Quality Control Validation",
                                value=True,
                                info="Use LLM-as-a-Judge to validate and improve content quality",
                            )

                            with gr.Row():
                                generate_btn = gr.Button(
                                    "🚀 Generate Profile", variant="primary", size="lg"
                                )
                                clear_btn = gr.Button("🗑️ Clear", variant="secondary")

                # Results section
                with gr.Row():
                    with gr.Column():
                        with gr.Tab("📄 Threat Intelligence Report"):
                            markdown_output = gr.Markdown(
                                value="Enter a tool name, then click **Generate Profile** to create a threat intelligence report.",
                                height=600,
                            )

                        # Quality Assessment Tab
                        with gr.Tab("📊 Quality Assessment"):
                            quality_output = gr.JSON(
                                label="Quality Validation Results", value=None, height=600
                            )

            # Tab 2: Report Library
            with gr.Tab("📚 Report Library"):
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### 🗂️ Saved Reports")

                        # Search and filter controls
                        with gr.Row():
                            search_input = gr.Textbox(
                                label="Search Reports",
                                placeholder="Search by tool name, category, or threat type...",
                                lines=1,
                            )
                            category_filter = gr.Dropdown(
                                choices=[
                                    "All",
                                    "malware",
                                    "apt",
                                    "tool",
                                    "vulnerability",
                                    "unknown",
                                ],
                                value="All",
                                label="Filter by Category",
                            )
                            search_btn = gr.Button("🔍 Search", variant="secondary")
                            refresh_btn = gr.Button("🔄 Refresh", variant="secondary")

                        # Report list
                        report_list = gr.Dataframe(
                            headers=["Tool Name", "Category", "Quality Score", "Created", "ID"],
                            value=load_report_list(),
                            interactive=False,
                            height=400,
                        )

                        # Report actions
                        with gr.Row():
                            selected_report_id = gr.Textbox(
                                label="Selected Report ID",
                                placeholder="Click on a report row to select it, then copy the ID here",
                                lines=1,
                            )
                            view_btn = gr.Button("👁️ View Report", variant="primary")
                            download_btn = gr.Button("💾 Download", variant="secondary")

                # Report viewer
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### 📖 Report Viewer")

                        with gr.Tab("📄 Report Content"):
                            viewed_report = gr.Markdown(
                                value="Select a report from the library above and click **View Report** to display its content.",
                                height=600,
                            )

                        with gr.Tab("📊 Report Quality"):
                            viewed_quality = gr.JSON(
                                label="Quality Assessment", value=None, height=600
                            )

        # Event handlers
        generate_btn.click(
            fn=generate_threat_profile,
            inputs=[tool_input, enable_quality],
            outputs=[markdown_output, quality_output],
            show_progress=True,
        )

        # Clear functionality
        def clear_all():
            return "", True, None, None

        clear_btn.click(
            fn=clear_all, outputs=[tool_input, enable_quality, markdown_output, quality_output]
        )

        # Report library event handlers
        search_btn.click(
            fn=search_reports, inputs=[search_input, category_filter], outputs=[report_list]
        )

        refresh_btn.click(fn=load_report_list, outputs=[report_list])

        view_btn.click(
            fn=view_report, inputs=[selected_report_id], outputs=[viewed_report, viewed_quality]
        )

        # Download functionality
        def get_download_link(report_id):
            if not STORAGE_ENABLED or not report_id:
                return "Storage not enabled or no report selected"

            try:
                url = report_service.get_download_url(report_id, "markdown")
                if url:
                    return f"[Download Report]({url})"
                else:
                    return "Download not available"
            except Exception as e:
                return f"Error generating download link: {e}"

        download_btn.click(
            fn=get_download_link,
            inputs=[selected_report_id],
            outputs=[gr.Markdown(visible=False)],  # We'll improve this later
        )

    interface.launch(
        server_name="0.0.0.0", server_port=7860, share=True, show_error=True, show_api=False
    )


if __name__ == "__main__":
    create_ui()
