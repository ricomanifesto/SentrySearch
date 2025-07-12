
# 🔍 SentrySearch

<div align="center">
  <img src="docs/assets/logo.png" alt="SentrySearch Logo" width="400" />
</div>

**AI-Powered Threat Intelligence Platform**

SentrySearch leverages Anthropic's Claude with web search capabilities to generate comprehensive threat intelligence profiles for malware, attack tools, and targeted technologies.

## 🌟 Features

- **Real-time Web Research**: Uses Anthropic's web search API for current threat intelligence
- **Comprehensive Profiles**: Technical details, threat landscape, detection guidance
- **Source Transparency**: Shows exactly what sources were used for research
- **Dual Intelligence**: Understand both attack tools and why technologies are targeted
- **Export Capabilities**: Download reports as structured markdown files

## 🚀 How to Use

1. **Get API Key**: Sign up at [Anthropic Console](https://console.anthropic.com/) and get your API key
2. **Enter Target**: Input any malware name, attack tool, or technology (e.g., "ShadowPad", "SAP NetWeaver", "AnyDesk")
3. **Generate Profile**: Click "Generate Profile" to create comprehensive threat intelligence
4. **Review Sources**: Check the "Web Search Sources" section to see research methodology
5. **Download Report**: Export the markdown report for further analysis

## 🎯 Example Queries

### Attack Tools & Malware
- `ShadowPad` - Advanced backdoor malware
- `Cobalt Strike` - Penetration testing framework
- `BumbleBee` - Malware loader
- `StealC` - Information stealer

### Targeted Technologies
- `SAP NetWeaver` - Enterprise application platform
- `Microsoft Exchange` - Email server platform
- `VMware vCenter` - Virtualization management
- `AnyDesk` - Remote desktop software

## 🔧 Technical Details

Built with:
- **Anthropic Claude** with web search capabilities
- **Gradio** for the interactive web interface
- **Real-time research** for current threat intelligence

## 📚 Related Projects

- [SentryDigest](https://github.com/ricomanifesto/SentryDigest) - Cybersecurity news aggregator
- [SentryInsight](https://github.com/ricomanifesto/SentryInsight) - AI-powered threat analysis

---

**⚠️ Note**: This tool requires an Anthropic API key. The key is only used for your session and is not stored.