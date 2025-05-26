# 🔍 SentrySearch

**AI-Powered Threat Intelligence Platform**

SentrySearch leverages Anthropic's Claude with web search capabilities to generate comprehensive threat intelligence profiles for malware, attack tools, and targeted technologies.

## 🌟 Features

- **Real-time Web Research**: Uses Anthropic's web search API for current threat intelligence
- **Comprehensive Profiles**: Technical details, threat landscape, detection guidance
- **Source Transparency**: Shows exactly what sources were used for research
- **Dual Intelligence**: Understand both attack tools and why technologies are targeted
- **Export Capabilities**: Download reports as structured markdown files

## 🚀 Live Demo

**Access SentrySearch Here**: [SentrySearch](https://huggingface.co/spaces/ricomanifesto/SentrySearch)

## 📖 Usage

1. **Get API Key**: Sign up at [Anthropic Console](https://console.anthropic.com/) and get your API key
2. **Enter Target**: Input any malware name, attack tool, or technology (e.g., "ShadowPad", "SAP NetWeaver", "AnyDesk")
3. **Generate Profile**: Click "Generate Profile" to create comprehensive threat intelligence
4. **Review Sources**: Check the "Web Search Sources" section to see research methodology
5. **Download Report**: Export the markdown report for further analysis

## 🎯 Use Cases

### Attack Tools & Malware
- Understanding capabilities and persistence mechanisms
- Getting current IOCs and detection rules
- Learning about associated threat actors

### Targeted Technologies
- Understanding why systems are attractive targets
- Identifying attack surfaces and common vulnerabilities
- Assessing business risk and impact

## 🔧 Configuration

The application uses these key components:
- **Gradio**: Web interface framework
- **Anthropic Claude 3.5**: AI model with web search
- **Real-time Research**: Current threat intelligence gathering

## 📊 Output Format

Each threat intelligence profile includes:
- **Core Metadata**: Classification, trust scores, timeline
- **Web Search Sources**: Research methodology and source verification
- **Technical Details**: Architecture, capabilities, dependencies
- **Threat Intelligence**: Associated actors, campaigns, risk assessment
- **Detection & Mitigation**: Detection and response guidance
- **Operational Context**: Business impact, deployment patterns

## 📚 Related Projects

- [SentryDigest](https://github.com/ricomanifesto/SentryDigest) - Cybersecurity news aggregator
- [SentryInsight](https://github.com/ricomanifesto/SentryInsight) - AI-powered threat analysis
