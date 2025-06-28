# SentrySearch

AI-powered threat intelligence platform with hybrid search capabilities and dual deployment options.

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run application (auto-detects best structure)
python run_app.py
```

## 🏗️ Architecture Options

### **Production System (Recommended)**
- **Frontend**: Gradio web interface
- **Backend**: Cloudflare Workers + Pinecone
- **Search**: Hybrid vector + keyword search
- **Performance**: 50x faster (40ms response times)
- **Deployment**: Global edge via Cloudflare

### **Local Development System**
- **Frontend**: Gradio web interface  
- **Backend**: ChromaDB + local BM25
- **Search**: Local vector + keyword search
- **Performance**: Local processing (2000ms response times)
- **Deployment**: Single machine

## 📁 Project Structure

```
├── src/                    # Core application (organized)
├── docs/                   # Complete documentation
├── data/
│   ├── kv_data/           # Production search data
│   ├── traces/            # Execution traces
│   └── legacy/            # ChromaDB system backup
├── scripts/               # Utilities and migration tools
├── tests/                 # Test suite
├── worker.js              # Cloudflare Workers
├── app.py                 # Legacy entry point (compatibility)
├── ml_knowledge_base/     # ChromaDB vector database
└── run_app.py            # Universal launcher
```

## 🔧 Environment Setup

### For Production (Workers + Pinecone)
```bash
export WORKERS_URL="https://your-worker.workers.dev"
export ANTHROPIC_API_KEY="your-api-key"
```

### For Local Development (ChromaDB)
```bash
export ML_RETRIEVER_MODE="chromadb"
export ANTHROPIC_API_KEY="your-api-key"
```

## 🎯 Features

- **Threat Intelligence Generation**: AI-powered security analysis
- **Dual ML Systems**: Production Workers + local ChromaDB
- **Tracing & Debugging**: Comprehensive execution traces
- **Quality Control**: Automated content validation
- **Company Expertise**: Industry-specific recommendations
- **Hybrid Search**: Vector + keyword relevance

## 📖 Documentation

- [Migration Journey](docs/MIGRATION_BLOG_POST.md) - Complete architecture story
- [Configuration Guide](docs/CONFIGURATION_GUIDE.md) - Setup instructions  
- [Project Structure](PROJECT_STRUCTURE.md) - Detailed organization

## 🔄 System Compatibility

This repository supports both the original ChromaDB system and the new production Workers system:

- **Automatic Detection**: Chooses best available system
- **Graceful Fallbacks**: Workers failures fall back to ChromaDB
- **Legacy Preservation**: Original system fully maintained
- **Future Ready**: Production deployment capability

## 🚀 Deployment Options

### Local Development
```bash
python run_app.py
```

### Cloudflare Workers
```bash
wrangler deploy
```

### Legacy Compatibility
```bash
python app.py  # Direct legacy execution
```

## 📊 Performance Comparison

| System | Response Time | Deployment | Capacity |
|--------|---------------|------------|----------|
| ChromaDB (Local) | 2000ms | Single machine | 10-50 users |
| Workers + Pinecone | 40ms | Global edge | 1000+ users |

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Test with both systems
4. Submit pull request

---

*This project demonstrates production-ready AI architecture while maintaining full backward compatibility.*