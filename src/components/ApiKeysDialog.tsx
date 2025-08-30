import { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Eye, EyeOff, Key, Shield, Trash2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { secureStorage } from '@/lib/secure-storage';

interface ApiKeysDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const storageKeys = {
  openai: 'openai_key',
  anthropic: 'anthropic_key',
  gemini: 'gemini_key',
  openrouter: 'openrouter_key',
  proxy: 'cqlforge_proxy_url'
};

export const ApiKeysDialog = ({ open, onOpenChange }: ApiKeysDialogProps) => {
  const { toast } = useToast();
  const [openai, setOpenai] = useState('');
  const [anthropic, setAnthropic] = useState('');
  const [gemini, setGemini] = useState('');
  const [openrouter, setOpenrouter] = useState('');
  const [proxy, setProxy] = useState('');

  useEffect(() => {
    // Load existing keys on mount using secure storage
    const loadKeys = async () => {
      try {
        setOpenai(await secureStorage.decryptAndRetrieve(storageKeys.openai));
        setAnthropic(await secureStorage.decryptAndRetrieve(storageKeys.anthropic));
        setGemini(await secureStorage.decryptAndRetrieve(storageKeys.gemini));
        setOpenrouter(await secureStorage.decryptAndRetrieve(storageKeys.openrouter));
        setProxy(localStorage.getItem(storageKeys.proxy) || ''); // Proxy URL doesn't need encryption
      } catch (error) {
        console.error('Failed to load API keys:', error);
      }
    };
    
    if (open) {
      loadKeys();
    }
  }, [open]);

  const handleSave = async () => {
    try {
      await secureStorage.encryptAndStore(storageKeys.openai, openai.trim());
      await secureStorage.encryptAndStore(storageKeys.anthropic, anthropic.trim());
      await secureStorage.encryptAndStore(storageKeys.gemini, gemini.trim());
      await secureStorage.encryptAndStore(storageKeys.openrouter, openrouter.trim());
      localStorage.setItem(storageKeys.proxy, proxy.trim()); // Proxy URL doesn't need encryption
      toast({ title: 'Saved', description: 'API keys securely saved with encryption.' });
      onOpenChange(false);
    } catch (error) {
      console.error('Failed to save API keys:', error);
      toast({ title: 'Error', description: 'Failed to save API keys. Please try again.', variant: 'destructive' });
    }
  };

  const handleClear = async () => {
    try {
      await secureStorage.clearAll();
      localStorage.removeItem(storageKeys.proxy);
      setOpenai(''); setAnthropic(''); setGemini(''); setOpenrouter(''); setProxy('');
      toast({ title: 'Cleared', description: 'All keys securely removed from this browser.' });
    } catch (error) {
      console.error('Failed to clear API keys:', error);
      toast({ title: 'Error', description: 'Failed to clear API keys. Please try again.', variant: 'destructive' });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Configure API Keys (stored in your browser)</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid gap-2">
            <Label htmlFor="openai">OpenAI / Azure OpenAI</Label>
            <Input id="openai" value={openai} onChange={(e) => setOpenai(e.target.value)} placeholder="sk-... or AZURE_KEY" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="anthropic">Anthropic Claude</Label>
            <Input id="anthropic" value={anthropic} onChange={(e) => setAnthropic(e.target.value)} placeholder="anthropic-key" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="gemini">Google Gemini</Label>
            <Input id="gemini" value={gemini} onChange={(e) => setGemini(e.target.value)} placeholder="gemini-key" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="openrouter">OpenRouter</Label>
            <Input id="openrouter" value={openrouter} onChange={(e) => setOpenrouter(e.target.value)} placeholder="openrouter-key" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="proxy">Proxy URL (optional, for Fetch URL)</Label>
            <Input id="proxy" value={proxy} onChange={(e) => setProxy(e.target.value)} placeholder="https://your-proxy.example.com/fetch" />
          </div>
        </div>
        <DialogFooter className="gap-2">
          <Button variant="secondary" onClick={handleClear}>Clear All</Button>
          <Button onClick={handleSave}>Save</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default ApiKeysDialog;
