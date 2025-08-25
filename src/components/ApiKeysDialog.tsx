import { useEffect, useState } from 'react';
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';

interface ApiKeysDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const storageKeys = {
  openai: 'cqlforge_openai_key',
  anthropic: 'cqlforge_anthropic_key',
  gemini: 'cqlforge_gemini_key',
  openrouter: 'cqlforge_openrouter_key',
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
    if (open) {
      setOpenai(localStorage.getItem(storageKeys.openai) || '');
      setAnthropic(localStorage.getItem(storageKeys.anthropic) || '');
      setGemini(localStorage.getItem(storageKeys.gemini) || '');
      setOpenrouter(localStorage.getItem(storageKeys.openrouter) || '');
      setProxy(localStorage.getItem(storageKeys.proxy) || '');
    }
  }, [open]);

  const handleSave = () => {
    localStorage.setItem(storageKeys.openai, openai.trim());
    localStorage.setItem(storageKeys.anthropic, anthropic.trim());
    localStorage.setItem(storageKeys.gemini, gemini.trim());
    localStorage.setItem(storageKeys.openrouter, openrouter.trim());
    localStorage.setItem(storageKeys.proxy, proxy.trim());
    toast({ title: 'Saved', description: 'API keys and proxy URL saved locally.' });
    onOpenChange(false);
  };

  const handleClear = () => {
    Object.values(storageKeys).forEach((k) => localStorage.removeItem(k));
    setOpenai(''); setAnthropic(''); setGemini(''); setOpenrouter(''); setProxy('');
    toast({ title: 'Cleared', description: 'All keys removed from this browser.' });
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
