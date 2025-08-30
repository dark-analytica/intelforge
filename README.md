# IntelForge

**Universal Threat Hunting & Detection Engineering Platform**

IntelForge is a comprehensive cybersecurity platform that transforms threat intelligence into actionable detection rules across multiple SIEM platforms. Built for security analysts, threat hunters, and detection engineers, it provides vendor-neutral tools for IOC extraction, query generation, rule creation, and collaborative threat hunting.

## Features

### **🎯 Core Capabilities**
- **Universal IOC Extraction**: Extract IPs, domains, URLs, hashes, emails from text, files, and URLs
- **Multi-Vendor Query Generation**: Support for 6+ SIEM platforms with vendor-neutral approach
- **Universal Rule Generation**: Create Sigma and YARA rules from IOCs and threat intelligence
- **Enterprise CTI Integration**: 13+ premium threat intelligence providers
- **ML-Powered Analytics**: IOC scoring, threat attribution, and attack prediction
- **Community Platform**: Collaborative threat hunting with shared hunt packs

### **🏢 Supported SIEM Platforms**
- **CrowdStrike Falcon**: CQL (CrowdStrike Query Language)
- **Splunk Enterprise/Cloud**: SPL (Search Processing Language)
- **Microsoft Sentinel**: KQL (Kusto Query Language)
- **Elastic Security**: ES|QL (Elasticsearch Query Language)
- **IBM QRadar**: AQL (Ariel Query Language)
- **Google Chronicle**: UDM Search

### **🛡️ Detection Engineering**
- **Sigma Rule Generation**: Universal detection rules with multi-platform export
- **YARA Rule Creation**: Malware detection rules from IOCs and file samples
- **Query Optimization**: Performance suggestions and vendor-specific tuning
- **Field Mapping Editor**: Custom SIEM configurations and data source mapping
- **Automated Validation**: Syntax checking and rule testing across platforms

### **Export & Integration**
- **Multi-format Export**: CQL queries, CSV reports, STIX 2.1, JSON with TTP context
- **Enhanced CQL Bundles**: Queries with MITRE ATT&CK mappings and AI analysis context
- **Vendor-Aware Field Mapping**: Automatic field translation for different SIEM platforms

### **Security & Privacy**
- **Client-Side Processing**: All analysis happens locally in your browser
- **Encrypted API Key Storage**: AES-GCM encryption for sensitive credentials
- **Multiple AI Providers**: OpenAI, Anthropic Claude, Google Gemini, OpenRouter support
- **Offline Capability**: Core features work without internet connectivity

### **User Experience**
- **Dual Themes**: Sleek black analyst mode or retro green Pip-Boy terminal theme
- **Real-time Validation**: Live CQL syntax checking and field validation
- **Progress Tracking**: Visual feedback for long-running AI operations
- **Error Recovery**: Intelligent fallbacks and helpful error messages

## Getting Started

### Prerequisites

- Node.js 18+ and npm (recommended: install with [nvm](https://github.com/nvm-sh/nvm#installing-and-updating))
- Git

### Installation

```sh
# Clone the repository
git clone https://github.com/dark-analytica/cql-forge.git

# Navigate to the project directory
cd intelforge

# Install dependencies
npm install

# Start the development server
npm run dev
```

The application will be available at `http://localhost:5173`

### Building for Production

```sh
# Build the application
npm run build

# Preview the production build
npm run preview
```

## Technology Stack

This project is built with modern web technologies:

- **Frontend**: React 18 with TypeScript
- **Build Tool**: Vite for fast development and optimized builds
- **UI Framework**: shadcn/ui components with Radix UI primitives
- **Styling**: Tailwind CSS with custom theme support
- **State Management**: React Query for server state management
- **Routing**: React Router DOM
- **Backend**: Supabase for optional cloud features
- **Code Editor**: Monaco Editor for CQL syntax highlighting
- **Analytics**: Built-in usage analytics
- **Export Formats**: PDF generation, CSV, JSON, STIX 2.1

## Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Optional: Supabase configuration for cloud features
VITE_SUPABASE_URL=your_supabase_url
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key

# Optional: LLM Provider API Keys (for enhanced features)
VITE_OPENAI_API_KEY=your_openai_key
VITE_ANTHROPIC_API_KEY=your_anthropic_key
VITE_GOOGLE_API_KEY=your_google_key
```

### AI Provider Configuration

CQLForge supports multiple AI providers for enhanced analysis. **Recommended: Use OpenRouter for best browser compatibility.**

#### **Supported Providers**
- **OpenRouter** ⭐ (Recommended): Browser-friendly proxy supporting Claude, GPT, Gemini, and 100+ models
- **Anthropic Claude**: Direct API access (may have CORS issues in browsers)
- **OpenAI/Azure OpenAI**: Direct API access (may have CORS issues in browsers)  
- **Google Gemini**: Direct API access (may have CORS issues in browsers)

#### **CORS Issues & Solutions**
Direct API calls to AI providers are often blocked by browser security (CORS policy). If you encounter "Failed to fetch" errors:

1. **Use OpenRouter** (recommended): Get an API key from [openrouter.ai](https://openrouter.ai)
2. **Configure a CORS proxy**: Set up a proxy server for direct API calls
3. **Use browser extensions**: Install CORS-disabling extensions (not recommended for security)

Configure API keys through Settings → Configure API Keys in the application.

## Usage

### **Quick Start Workflow**
1. **Extract IOCs**: Paste threat reports, upload PDFs, or fetch URLs for automatic IOC extraction
2. **AI Analysis**: Enable AI filtering to reduce false positives and extract TTPs automatically  
3. **Generate CQL**: Select your SIEM vendor and convert IOCs into optimized queries
4. **Hunt Enhancement**: Apply AI-generated hunt suggestions based on MITRE ATT&CK framework
5. **Export & Deploy**: Export enhanced CQL bundles with TTP context for your security tools

### **🚀 Advanced Features**
- **Enterprise CTI APIs**: Recorded Future, CrowdStrike Falcon X, Mandiant, and 10+ more
- **ML Analytics Engine**: IOC risk scoring, threat actor attribution, attack vector prediction
- **Community Hunt Packs**: Collaborative threat hunting with expert-verified content
- **Universal Rule Export**: Deploy Sigma rules to Splunk, Elastic, QRadar, Sentinel, Chronicle
- **Automated Threat Correlation**: Cross-platform IOC analysis and campaign attribution
- **Performance Optimization**: Vendor-specific query tuning and efficiency recommendations

## Development

### Project Structure

```
src/
├── components/          # React components
│   ├── ui/             # shadcn/ui components
│   ├── IOCExtractor.tsx # IOC extraction logic
│   ├── CQLGenerator.tsx # CQL query generation
│   └── ...
├── hooks/              # Custom React hooks
├── lib/                # Utility functions and configurations
├── pages/              # Route components
└── integrations/       # External service integrations
```

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run build:dev` - Build in development mode
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

## Deployment

### Static Hosting

The application builds to static files and can be deployed to any static hosting service:

- Netlify
- Vercel
- GitHub Pages
- AWS S3 + CloudFront
- Azure Static Web Apps

### Docker Deployment

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "run", "preview"]
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, feature requests, or questions:

1. Check the built-in Help documentation (Help button in the app)
2. Review existing GitHub issues
3. Create a new issue with detailed information

## Recent Updates

### **✅ MITRE ATT&CK Integration (Completed)**
- **Comprehensive Technique Database**: 20+ MITRE ATT&CK techniques with full metadata
- **Enhanced TTP Extraction**: AI-powered extraction with authoritative technique descriptions
- **Improved Hunt Suggestions**: Context-aware recommendations using Pyramid of Pain framework
- **Better TTP Cards**: Clean evidence excerpts and professional technique displays

### **✅ Hunt Template Library (Enhanced)**
- **8+ Advanced Hunt Templates**: PowerShell analysis, process injection, C2 detection, etc.
- **Dynamic Template Generation**: Fallback system for missing hunt scenarios
- **Multi-IOC Correlation**: Cross-reference different IOC types for campaign attribution
- **Temporal Analysis**: Timeline-based hunting for attack progression

## Roadmap

### **🚀 Completed in Latest Release**
- ✅ **Phase 2**: Multi-vendor expansion (6 SIEM platforms)
- ✅ **Phase 3**: Advanced features (Sigma/YARA rules, Enterprise CTI, ML analytics)
- ✅ **Security Hardening**: CSP headers, input validation, secure architecture
- ✅ **Community Platform**: Collaborative hunt pack sharing and validation

### **🎯 Upcoming Features**
- [ ] **Authentication System**: User accounts and subscription management
- [ ] **Production Deployment**: Cloudflare hosting with custom domain
- [ ] **API Monetization**: Usage-based pricing and enterprise features
- [ ] **SSO Integration**: SAML and OIDC for enterprise customers
- [ ] **Advanced Analytics**: Threat landscape insights and trending IOCs
