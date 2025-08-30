# IntelForge Deployment Strategy

## 🎯 **Deployment Overview**

### **Hosting Architecture**
- **Frontend**: Static site deployment (Cloudflare Pages/Vercel)
- **Backend**: Serverless functions (Cloudflare Workers/Vercel Functions)
- **Database**: PostgreSQL (Supabase/Neon)
- **CDN**: Cloudflare for global distribution and security
- **Domain**: Custom domain with Cloudflare DNS and security features

## 🌐 **Cloudflare Integration Strategy**

### **Domain & DNS Configuration**
```yaml
Domain: intelforge.com (or your chosen domain)
DNS Records:
  - Type: A, Name: @, Value: Cloudflare IP
  - Type: CNAME, Name: www, Value: intelforge.com
  - Type: CNAME, Name: api, Value: api.intelforge.com
  - Type: TXT, Name: @, Value: "v=spf1 include:_spf.google.com ~all"
```

### **Cloudflare Security Features**
```yaml
Security Settings:
  SSL/TLS: Full (Strict)
  Min TLS Version: 1.2
  HSTS: Enabled (6 months)
  Bot Fight Mode: Enabled
  DDoS Protection: Enabled
  WAF: Custom rules for threat intelligence
  
Firewall Rules:
  - Block known malicious IPs
  - Rate limit API endpoints (100 req/min)
  - Challenge suspicious bot traffic
  - Block countries if needed (compliance)
  
Page Rules:
  - Cache static assets (24h)
  - Security headers for all pages
  - Redirect HTTP to HTTPS
```

## 🏗️ **Architecture Options**

### **Option 1: Cloudflare Pages + Workers (Recommended)**

#### **Advantages**
- **Performance**: Global edge deployment
- **Security**: Built-in DDoS, WAF, bot protection
- **Cost**: Generous free tier, pay-as-you-scale
- **Integration**: Seamless Cloudflare ecosystem
- **Serverless**: No server management needed

#### **Implementation**
```yaml
Frontend (Cloudflare Pages):
  - Build: npm run build
  - Output: dist/
  - Custom domain: intelforge.com
  - Environment variables via dashboard
  
Backend (Cloudflare Workers):
  - API routes: /api/*
  - Authentication: JWT + KV storage
  - Database: D1 (SQLite) or external PostgreSQL
  - File storage: R2 (S3-compatible)
  
Configuration:
  wrangler.toml:
    name: "intelforge-api"
    main: "src/worker.ts"
    compatibility_date: "2024-08-29"
    
    [vars]
    ENVIRONMENT = "production"
    
    [[kv_namespaces]]
    binding = "SESSIONS"
    id = "your-kv-namespace-id"
```

### **Option 2: Vercel + Supabase**

#### **Advantages**
- **Developer Experience**: Excellent DX and tooling
- **Database**: Full PostgreSQL with real-time features
- **Authentication**: Built-in auth with social providers
- **Edge Functions**: Global serverless functions

#### **Implementation**
```yaml
Frontend (Vercel):
  - Framework: Vite + React
  - Build: npm run build
  - Custom domain: intelforge.com
  - Environment variables via dashboard
  
Backend (Vercel Functions):
  - API routes: /api/*
  - Runtime: Node.js 18
  - Database: Supabase PostgreSQL
  - Authentication: Supabase Auth
  
Configuration:
  vercel.json:
    {
      "functions": {
        "app/api/**/*.ts": {
          "runtime": "nodejs18.x"
        }
      },
      "headers": [
        {
          "source": "/(.*)",
          "headers": [
            {
              "key": "X-Frame-Options",
              "value": "DENY"
            }
          ]
        }
      ]
    }
```

## 🔐 **Authentication & User Management**

### **User Schema**
```sql
-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255),
  display_name VARCHAR(100),
  avatar_url TEXT,
  role VARCHAR(20) DEFAULT 'free',
  subscription_tier VARCHAR(20) DEFAULT 'free',
  subscription_expires TIMESTAMP,
  api_quota_used INTEGER DEFAULT 0,
  api_quota_limit INTEGER DEFAULT 1000,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  last_login TIMESTAMP,
  email_verified BOOLEAN DEFAULT FALSE,
  two_factor_enabled BOOLEAN DEFAULT FALSE
);

-- User profiles and preferences
CREATE TABLE user_profiles (
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  preferences JSONB DEFAULT '{}',
  saved_queries JSONB DEFAULT '[]',
  favorite_hunt_packs JSONB DEFAULT '[]',
  custom_field_mappings JSONB DEFAULT '{}',
  api_keys_encrypted TEXT, -- Encrypted user API keys
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Hunt packs with user ownership
CREATE TABLE hunt_packs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  author_id UUID REFERENCES users(id),
  visibility VARCHAR(20) DEFAULT 'public',
  content JSONB NOT NULL,
  tags TEXT[] DEFAULT '{}',
  downloads INTEGER DEFAULT 0,
  stars INTEGER DEFAULT 0,
  rating DECIMAL(3,2) DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- API usage tracking
CREATE TABLE api_usage (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id),
  endpoint VARCHAR(255),
  tokens_used INTEGER DEFAULT 0,
  cost_cents INTEGER DEFAULT 0,
  timestamp TIMESTAMP DEFAULT NOW(),
  ip_address INET,
  user_agent TEXT
);
```

### **Authentication Flow**
```typescript
// JWT-based authentication with refresh tokens
interface AuthTokens {
  accessToken: string;  // 15 minutes
  refreshToken: string; // 30 days
  user: {
    id: string;
    email: string;
    role: string;
    subscription: {
      tier: string;
      expires: string;
      quotas: {
        apiCalls: number;
        huntPacks: number;
        storage: number;
      };
    };
  };
}

// Subscription tiers
const SUBSCRIPTION_TIERS = {
  free: {
    apiCalls: 1000,
    huntPacks: 5,
    storage: 100, // MB
    features: ['basic_queries', 'ioc_extraction', 'community_packs']
  },
  pro: {
    apiCalls: 10000,
    huntPacks: 50,
    storage: 1000, // MB
    features: ['advanced_queries', 'sigma_rules', 'yara_rules', 'private_packs']
  },
  enterprise: {
    apiCalls: 100000,
    huntPacks: -1, // unlimited
    storage: 10000, // MB
    features: ['enterprise_cti', 'ml_analytics', 'sso', 'priority_support']
  }
};
```

## 💰 **Monetization Strategy**

### **Subscription Plans**
```yaml
Free Tier:
  Price: $0/month
  Features:
    - 1,000 API calls/month
    - Basic IOC extraction
    - Community hunt packs (read-only)
    - 5 saved queries
    - Standard support
  
Pro Tier:
  Price: $29/month
  Features:
    - 10,000 API calls/month
    - Sigma & YARA rule generation
    - Private hunt packs
    - 50 saved queries
    - Custom field mappings
    - Priority support
    
Enterprise Tier:
  Price: $199/month
  Features:
    - 100,000 API calls/month
    - Enterprise CTI APIs
    - ML-powered analytics
    - Unlimited hunt packs
    - SSO integration
    - Dedicated support
    - Custom integrations
```

### **API Pricing Model**
```typescript
const API_COSTS = {
  ioc_extraction: 0.001,      // $0.001 per request
  query_generation: 0.01,     // $0.01 per query
  sigma_rule: 0.05,          // $0.05 per rule
  yara_rule: 0.05,           // $0.05 per rule
  cti_enrichment: 0.02,      // $0.02 per IOC
  ml_analysis: 0.10,         // $0.10 per analysis
  enterprise_cti: 0.25       // $0.25 per query
};
```

## 🚀 **Deployment Pipeline**

### **CI/CD Configuration**
```yaml
# .github/workflows/deploy.yml
name: Deploy to Production
on:
  push:
    branches: [main]
    
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm ci
      - run: npm run test
      - run: npm run lint
      - run: npm run type-check
      
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run security audit
        run: npm audit --audit-level moderate
      - name: Check for secrets
        uses: trufflesecurity/trufflehog@main
        
  deploy:
    needs: [test, security]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Deploy to Cloudflare Pages
        uses: cloudflare/pages-action@v1
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          projectName: intelforge
          directory: dist
```

### **Environment Configuration**
```bash
# Production environment variables
VITE_APP_ENV=production
VITE_API_BASE_URL=https://api.intelforge.com
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your_anon_key
VITE_CLOUDFLARE_TURNSTILE_KEY=your_turnstile_key
VITE_STRIPE_PUBLISHABLE_KEY=pk_live_...
VITE_ANALYTICS_ID=your_analytics_id

# Server-side only (Worker/Function environment)
DATABASE_URL=postgresql://...
JWT_SECRET=your_jwt_secret_256_bit
ENCRYPTION_KEY=your_encryption_key_256_bit
STRIPE_SECRET_KEY=sk_live_...
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
RECORDED_FUTURE_API_KEY=...
CROWDSTRIKE_CLIENT_ID=...
CROWDSTRIKE_CLIENT_SECRET=...
```

## 📊 **Monitoring & Analytics**

### **Application Monitoring**
```typescript
// Monitoring configuration
const monitoring = {
  // Error tracking
  sentry: {
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV,
    tracesSampleRate: 0.1
  },
  
  // Performance monitoring
  analytics: {
    provider: 'mixpanel', // or 'amplitude'
    events: [
      'user_signup',
      'query_generated',
      'hunt_pack_created',
      'api_call_made',
      'subscription_upgraded'
    ]
  },
  
  // Infrastructure monitoring
  cloudflare: {
    analytics: true,
    webVitals: true,
    securityEvents: true
  }
};
```

### **Key Metrics to Track**
```yaml
Business Metrics:
  - Monthly Active Users (MAU)
  - Conversion rate (free to paid)
  - Churn rate
  - Average Revenue Per User (ARPU)
  - API usage per user
  
Technical Metrics:
  - Page load times
  - API response times
  - Error rates
  - Uptime/availability
  - Security incidents
  
User Engagement:
  - Queries generated per session
  - Hunt packs created/downloaded
  - Time spent in application
  - Feature adoption rates
```

## 🔧 **Infrastructure Requirements**

### **Minimum Requirements**
```yaml
Cloudflare Plan: Pro ($20/month)
  - Advanced DDoS protection
  - WAF with custom rules
  - Page Rules (20 included)
  - Analytics & insights
  
Database: Supabase Pro ($25/month)
  - 8GB database
  - 100GB bandwidth
  - Daily backups
  - 99.9% uptime SLA
  
Storage: Cloudflare R2
  - $0.015/GB/month
  - $0.36/million requests
  - No egress fees
```

### **Scaling Considerations**
```yaml
Traffic Scaling:
  - Cloudflare handles global CDN
  - Workers auto-scale to demand
  - Database connection pooling
  - Redis caching for hot data
  
Cost Optimization:
  - Cache static assets (24h)
  - Compress API responses
  - Optimize database queries
  - Use edge computing for IOC extraction
  
Performance:
  - Lazy load components
  - Code splitting by route
  - Service worker for offline capability
  - Progressive Web App features
```

## 📋 **Pre-Launch Checklist**

### **Technical Requirements**
- [ ] SSL certificate configured
- [ ] Custom domain pointing to Cloudflare
- [ ] Environment variables set
- [ ] Database migrations run
- [ ] API endpoints tested
- [ ] Authentication flow working
- [ ] Payment processing integrated
- [ ] Error monitoring configured
- [ ] Analytics tracking implemented
- [ ] Security headers configured

### **Legal & Compliance**
- [ ] Privacy Policy created
- [ ] Terms of Service written
- [ ] GDPR compliance implemented
- [ ] Cookie consent banner
- [ ] Data retention policies
- [ ] Security incident response plan
- [ ] Backup and recovery procedures

### **Business Requirements**
- [ ] Pricing plans configured
- [ ] Subscription management working
- [ ] Customer support system
- [ ] Documentation website
- [ ] Marketing site content
- [ ] SEO optimization
- [ ] Social media accounts
- [ ] Launch announcement prepared

## 🎯 **Go-Live Timeline**

### **Phase 1: Infrastructure Setup (Week 1)**
- Domain registration and Cloudflare setup
- Database provisioning and schema deployment
- CI/CD pipeline configuration
- Basic authentication implementation

### **Phase 2: Core Features (Week 2-3)**
- User registration and login
- Subscription management
- API proxy implementation
- Security hardening

### **Phase 3: Testing & Optimization (Week 4)**
- Load testing
- Security penetration testing
- Performance optimization
- Bug fixes and polish

### **Phase 4: Launch Preparation (Week 5)**
- Documentation completion
- Marketing material creation
- Beta user testing
- Final security review

### **Phase 5: Go-Live (Week 6)**
- Production deployment
- DNS cutover
- Monitoring setup
- Launch announcement

## 💡 **Success Metrics**

### **30-Day Goals**
- 1,000 registered users
- 100 paid subscribers
- 99.9% uptime
- <2s average page load time
- 0 security incidents

### **90-Day Goals**
- 5,000 registered users
- 500 paid subscribers
- $15,000 MRR
- 50+ community hunt packs
- Enterprise customer pipeline

This deployment strategy provides a robust, scalable foundation for IntelForge's production launch with Cloudflare's security features and global performance optimization.
