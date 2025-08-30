# IntelForge Authentication Strategy

## 🎯 **Authentication Approach (No Initial Charging)**

### **Phase 1: Free Platform Launch**
- **No payment processing initially** - Focus on user acquisition and platform validation
- **Simple authentication** - Email/password with optional social login
- **Feature gating** - Prepare infrastructure for future monetization without charging
- **Usage tracking** - Monitor API calls and feature usage for future pricing models

## 🔐 **Authentication Architecture**

### **Recommended Stack: Supabase Auth**
```typescript
// Benefits of Supabase Auth
const authBenefits = {
  features: [
    'Email/password authentication',
    'Social login (Google, GitHub, etc.)',
    'Email verification',
    'Password reset flows',
    'JWT token management',
    'Row Level Security (RLS)',
    'Real-time subscriptions'
  ],
  advantages: [
    'No backend code required',
    'Built-in security best practices',
    'Scales automatically',
    'Free tier: 50,000 MAU',
    'Easy integration with existing Supabase setup'
  ]
};
```

### **User Schema Design**
```sql
-- Users table (managed by Supabase Auth)
-- Supabase automatically creates auth.users

-- Extended user profiles
CREATE TABLE user_profiles (
  id UUID REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  display_name VARCHAR(100),
  avatar_url TEXT,
  
  -- Usage tracking (for future monetization)
  api_calls_used INTEGER DEFAULT 0,
  api_calls_limit INTEGER DEFAULT 5000, -- Generous free tier
  
  -- Feature flags
  features_enabled JSONB DEFAULT '{
    "ioc_extraction": true,
    "query_generation": true,
    "sigma_rules": true,
    "yara_rules": false,
    "enterprise_cti": false,
    "ml_analytics": false,
    "private_hunt_packs": false
  }',
  
  -- Preferences
  preferences JSONB DEFAULT '{
    "theme": "dark",
    "default_siem": "crowdstrike",
    "notifications": true
  }',
  
  -- Saved data
  saved_queries JSONB DEFAULT '[]',
  saved_hunt_packs JSONB DEFAULT '[]',
  custom_field_mappings JSONB DEFAULT '{}',
  
  -- Metadata
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  last_login TIMESTAMP,
  onboarding_completed BOOLEAN DEFAULT FALSE
);

-- Usage tracking for future analytics
CREATE TABLE api_usage_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  endpoint VARCHAR(255) NOT NULL,
  method VARCHAR(10) NOT NULL,
  tokens_used INTEGER DEFAULT 0,
  processing_time_ms INTEGER,
  success BOOLEAN DEFAULT TRUE,
  error_message TEXT,
  metadata JSONB DEFAULT '{}',
  timestamp TIMESTAMP DEFAULT NOW()
);

-- Hunt packs with user ownership
CREATE TABLE hunt_packs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  author_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  visibility VARCHAR(20) DEFAULT 'public', -- public, private, shared
  content JSONB NOT NULL,
  tags TEXT[] DEFAULT '{}',
  
  -- Community features
  downloads INTEGER DEFAULT 0,
  stars INTEGER DEFAULT 0,
  forks INTEGER DEFAULT 0,
  
  -- Metadata
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  
  -- Search optimization
  search_vector tsvector GENERATED ALWAYS AS (
    to_tsvector('english', name || ' ' || COALESCE(description, ''))
  ) STORED
);

-- Row Level Security policies
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE hunt_packs ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_usage_logs ENABLE ROW LEVEL SECURITY;

-- Users can only access their own data
CREATE POLICY "Users can view own profile" ON user_profiles
  FOR SELECT USING (auth.uid() = id);
  
CREATE POLICY "Users can update own profile" ON user_profiles
  FOR UPDATE USING (auth.uid() = id);

-- Hunt packs visibility rules
CREATE POLICY "Public hunt packs visible to all" ON hunt_packs
  FOR SELECT USING (visibility = 'public' OR auth.uid() = author_id);
  
CREATE POLICY "Users can create hunt packs" ON hunt_packs
  FOR INSERT WITH CHECK (auth.uid() = author_id);
```

## 🚀 **Implementation Plan**

### **Step 1: Supabase Setup**
```bash
# Install Supabase CLI
npm install -g @supabase/cli

# Initialize Supabase project
supabase init

# Start local development
supabase start

# Deploy to production
supabase db push
```

### **Step 2: React Integration**
```typescript
// src/lib/supabase.ts
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Auth context
export interface AuthUser {
  id: string;
  email: string;
  displayName?: string;
  avatarUrl?: string;
  profile?: UserProfile;
}

export interface UserProfile {
  apiCallsUsed: number;
  apiCallsLimit: number;
  featuresEnabled: Record<string, boolean>;
  preferences: Record<string, any>;
  savedQueries: any[];
  onboardingCompleted: boolean;
}
```

### **Step 3: Authentication Components**
```typescript
// src/components/auth/AuthProvider.tsx
import { createContext, useContext, useEffect, useState } from 'react';
import { supabase } from '@/lib/supabase';

interface AuthContextType {
  user: AuthUser | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<void>;
  signUp: (email: string, password: string, displayName?: string) => Promise<void>;
  signOut: () => Promise<void>;
  updateProfile: (updates: Partial<UserProfile>) => Promise<void>;
}

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Get initial session
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session?.user) {
        loadUserProfile(session.user);
      }
      setLoading(false);
    });

    // Listen for auth changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      async (event, session) => {
        if (session?.user) {
          await loadUserProfile(session.user);
        } else {
          setUser(null);
        }
        setLoading(false);
      }
    );

    return () => subscription.unsubscribe();
  }, []);

  const loadUserProfile = async (authUser: any) => {
    const { data: profile } = await supabase
      .from('user_profiles')
      .select('*')
      .eq('id', authUser.id)
      .single();

    setUser({
      id: authUser.id,
      email: authUser.email,
      displayName: profile?.display_name,
      avatarUrl: profile?.avatar_url,
      profile: profile ? {
        apiCallsUsed: profile.api_calls_used,
        apiCallsLimit: profile.api_calls_limit,
        featuresEnabled: profile.features_enabled,
        preferences: profile.preferences,
        savedQueries: profile.saved_queries,
        onboardingCompleted: profile.onboarding_completed
      } : undefined
    });
  };

  // ... implement auth methods
};
```

## 🎯 **Feature Gating Strategy**

### **Free Tier Features (No Payment Required)**
```typescript
const FREE_TIER_FEATURES = {
  // Core features - always available
  ioc_extraction: true,
  query_generation: true,
  basic_sigma_rules: true,
  community_hunt_packs_read: true,
  
  // Limited features
  api_calls_limit: 5000, // per month
  saved_queries_limit: 25,
  hunt_packs_limit: 5,
  
  // Disabled features (future paid tiers)
  yara_rules: false,
  enterprise_cti: false,
  ml_analytics: false,
  private_hunt_packs: false,
  advanced_sigma_export: false,
  priority_support: false
};

// Usage tracking middleware
export const trackAPIUsage = async (userId: string, endpoint: string) => {
  const { data: profile } = await supabase
    .from('user_profiles')
    .select('api_calls_used, api_calls_limit')
    .eq('id', userId)
    .single();

  if (profile.api_calls_used >= profile.api_calls_limit) {
    throw new Error('API usage limit exceeded. Upgrade to Pro for higher limits.');
  }

  // Increment usage
  await supabase
    .from('user_profiles')
    .update({ 
      api_calls_used: profile.api_calls_used + 1,
      updated_at: new Date().toISOString()
    })
    .eq('id', userId);

  // Log usage for analytics
  await supabase
    .from('api_usage_logs')
    .insert({
      user_id: userId,
      endpoint,
      method: 'POST',
      tokens_used: 1
    });
};
```

## 📊 **Analytics & Metrics**

### **Key Metrics to Track**
```typescript
interface UserAnalytics {
  // Engagement metrics
  dailyActiveUsers: number;
  monthlyActiveUsers: number;
  sessionDuration: number;
  featuresUsed: string[];
  
  // Usage metrics
  queriesGenerated: number;
  iocsExtracted: number;
  huntPacksCreated: number;
  huntPacksDownloaded: number;
  
  // Conversion indicators
  apiLimitReached: boolean;
  featureRequestsBlocked: number;
  upgradePageVisits: number;
  
  // Retention metrics
  daysSinceSignup: number;
  lastActiveDate: Date;
  onboardingCompleted: boolean;
}

// Analytics dashboard queries
const getAnalytics = async () => {
  const { data: users } = await supabase
    .from('user_profiles')
    .select('*');
    
  const { data: usage } = await supabase
    .from('api_usage_logs')
    .select('*')
    .gte('timestamp', new Date(Date.now() - 30 * 24 * 60 * 60 * 1000));
    
  return {
    totalUsers: users.length,
    activeUsers: usage.filter(u => u.timestamp > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)).length,
    apiCallsThisMonth: usage.length,
    averageCallsPerUser: usage.length / users.length
  };
};
```

## 🔄 **Migration to Paid Tiers (Future)**

### **Preparation for Monetization**
```typescript
// Future subscription management
interface SubscriptionTier {
  id: string;
  name: string;
  price: number; // cents per month
  features: Record<string, boolean>;
  limits: {
    apiCalls: number;
    savedQueries: number;
    huntPacks: number;
    storage: number; // MB
  };
}

const SUBSCRIPTION_TIERS: SubscriptionTier[] = [
  {
    id: 'free',
    name: 'Community',
    price: 0,
    features: FREE_TIER_FEATURES,
    limits: {
      apiCalls: 5000,
      savedQueries: 25,
      huntPacks: 5,
      storage: 100
    }
  },
  {
    id: 'pro',
    name: 'Professional',
    price: 1900, // $19/month
    features: {
      ...FREE_TIER_FEATURES,
      yara_rules: true,
      private_hunt_packs: true,
      advanced_sigma_export: true,
      priority_support: true
    },
    limits: {
      apiCalls: 50000,
      savedQueries: 250,
      huntPacks: 50,
      storage: 1000
    }
  }
  // Enterprise tier to be added later
];
```

## 🚀 **Implementation Timeline**

### **Week 1: Basic Authentication**
- Set up Supabase project and database schema
- Implement sign up/sign in components
- Add user profile management
- Basic feature gating

### **Week 2: Usage Tracking**
- API usage middleware
- Analytics dashboard (admin)
- User dashboard showing usage
- Onboarding flow

### **Week 3: Community Features**
- Hunt pack creation/sharing
- User profiles and avatars
- Social features (stars, downloads)
- Search and discovery

### **Week 4: Polish & Testing**
- Error handling and edge cases
- Performance optimization
- Security audit
- User testing and feedback

## 💡 **Key Benefits of This Approach**

### **Technical Advantages**
- **No payment complexity** - Focus on product-market fit
- **Scalable architecture** - Ready for future monetization
- **Rich analytics** - Understand user behavior and conversion points
- **Security best practices** - Supabase handles auth security

### **Business Advantages**
- **Lower barrier to entry** - Users can try full platform
- **Viral growth potential** - Community features encourage sharing
- **Data-driven pricing** - Real usage data informs future pricing
- **User feedback** - Build features users actually want before charging

### **User Experience**
- **Immediate value** - No payment friction for core features
- **Progressive disclosure** - Introduce advanced features naturally
- **Community building** - Collaborative platform encourages engagement
- **Trust building** - Demonstrate value before asking for payment

This authentication strategy positions IntelForge for rapid user acquisition while building the foundation for future monetization based on real user behavior and feature demand.
