import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { Fingerprint, KeyRound, LockKeyhole, Copy, Plus, ShieldCheck, Trash2, Zap, LoaderCircle, ShieldAlert, Check, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import "./App.css";

type Account = { id: string; name: string };
type Code = { id: string; code: string; remaining: number };

function App() {
  const [unlocked, setUnlocked] = useState(false);
  const [authBusy, setAuthBusy] = useState(true);
  const [authError, setAuthError] = useState("");
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [codes, setCodes] = useState<Record<string, Code>>({});
  const [quickSecret, setQuickSecret] = useState("");
  const [quickCode, setQuickCode] = useState<Code | null>(null);
  const [quickError, setQuickError] = useState("");
  const [copyError, setCopyError] = useState("");
  const [copied, setCopied] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [newSecret, setNewSecret] = useState("");
  const [formError, setFormError] = useState("");
  const [busy, setBusy] = useState(false);
  const didStart = useRef(false);
  const quickActive = useRef(false);

  const loadData = useCallback(async () => {
    const [nextAccounts, nextCodes] = await Promise.all([
      invoke<Account[]>("list_accounts"),
      invoke<Code[]>("list_codes"),
    ]);
    setAccounts(nextAccounts);
    setCodes(Object.fromEntries(nextCodes.map((item) => [item.id, item])));
  }, []);

  const authenticate = useCallback(async () => {
    quickActive.current = false;
    setAuthBusy(true);
    setAuthError("");
    try {
      await invoke("verify_hello");
      setUnlocked(true);
      await loadData();
    } catch (error) {
      setUnlocked(false);
      setAuthError(String(error));
    } finally {
      setAuthBusy(false);
    }
  }, [loadData]);

  useEffect(() => {
    if (didStart.current) return;
    didStart.current = true;
    void authenticate();
  }, [authenticate]);

  useEffect(() => {
    if (!unlocked) return;
    const refresh = async () => {
      try {
        const [next, quick] = await Promise.all([
          invoke<Code[]>("list_codes"),
          invoke<Code | null>("refresh_quick_code"),
        ]);
        setCodes(Object.fromEntries(next.map((item) => [item.id, item])));
        if (quickActive.current) setQuickCode(quick);
      } catch (error) {
        setAuthError(String(error));
        setUnlocked(false);
        setCodes({});
        setQuickCode(null);
        setQuickSecret("");
        quickActive.current = false;
        void authenticate();
      }
    };
    const tick = window.setInterval(refresh, 1000);
    const recheck = window.setTimeout(() => {
      setUnlocked(false);
      setCodes({});
      setQuickCode(null);
      setQuickSecret("");
      quickActive.current = false;
      void authenticate();
    }, 60 * 60 * 1000);
    return () => { window.clearInterval(tick); window.clearTimeout(recheck); };
  }, [unlocked, authenticate]);

  const copyCode = async (code: string, id: string) => {
    setCopyError("");
    try {
      await writeText(code);
      setCopied(id);
      window.setTimeout(() => setCopied((current) => current === id ? "" : current), 1500);
    } catch {
      setCopyError("Не удалось скопировать код. Попробуйте ещё раз.");
    }
  };

  const generateQuickCode = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setQuickError("");
    setQuickCode(null);
    try {
      const result = await invoke<Code>("generate_code", { secret: quickSecret });
      setQuickCode(result);
      setQuickSecret("");
      quickActive.current = true;
    } catch (error) {
      setQuickError(String(error));
    }
  };

  const saveAccount = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError("");
    setBusy(true);
    try {
      await invoke("add_account", { name: newName, secret: newSecret });
      setNewName("");
      setNewSecret("");
      setDialogOpen(false);
      await loadData();
    } catch (error) {
      setFormError(String(error));
    } finally {
      setBusy(false);
    }
  };

  const deleteAccount = async (id: string) => {
    try {
      await invoke("remove_account", { id });
      await loadData();
    } catch (error) {
      setAuthError(String(error));
    }
  };

  if (!unlocked) {
    return (
      <TooltipProvider>
        <main className="lock-shell">
          <Card className="lock-card">
            <CardHeader className="items-center text-center">
              <div className="brand-mark lock-mark"><KeyRound size={23} /></div>
              <CardTitle className="mt-2 text-2xl">2FA Manager</CardTitle>
              <CardDescription>Ваши коды всегда под рукой</CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              {authError ? (
                <Alert variant="destructive">
                  <ShieldAlert />
                  <AlertTitle>Не удалось войти</AlertTitle>
                  <AlertDescription>{authError}</AlertDescription>
                </Alert>
              ) : (
                <p className="text-center text-sm text-muted-foreground">Подтвердите личность через Windows Hello, чтобы открыть хранилище.</p>
              )}
              <Button className="w-full" size="lg" onClick={() => void authenticate()} disabled={authBusy}>
                {authBusy ? <LoaderCircle className="animate-spin" /> : <Fingerprint />}
                {authBusy ? "Ожидание Windows Hello…" : "Войти через Windows Hello"}
              </Button>
              <div className="secure-note"><LockKeyhole size={14} /> Секреты зашифрованы вашей учётной записью Windows</div>
            </CardContent>
          </Card>
        </main>
      </TooltipProvider>
    );
  }

  return (
    <TooltipProvider>
      <main className="app-shell">
        <header className="topbar">
          <div className="brand"><div className="brand-mark"><KeyRound size={19} /></div><span>2FA <span className="brand-light">Manager</span></span></div>
          <div className="secure-pill"><ShieldCheck size={15} /> Защищено Windows Hello</div>
        </header>

        <section className="welcome-row">
          <div>
            <p className="eyebrow">ВАШЕ ХРАНИЛИЩЕ</p>
            <h1>Коды доступа</h1>
            <p className="subtitle">Одно касание — и код уже в буфере обмена.</p>
          </div>
          <Dialog open={dialogOpen} onOpenChange={(open) => { setDialogOpen(open); if (!open) { setFormError(""); setNewName(""); setNewSecret(""); } }}>
            <DialogTrigger asChild><Button size="lg"><Plus /> Добавить аккаунт</Button></DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Новый аккаунт</DialogTitle>
                <DialogDescription>Секрет останется на этом компьютере в зашифрованном хранилище.</DialogDescription>
              </DialogHeader>
              <form onSubmit={saveAccount} className="form-stack">
                <div className="field-stack"><Label htmlFor="account-name">Название</Label><Input id="account-name" autoFocus placeholder="Например, GitHub" value={newName} onChange={(e) => setNewName(e.target.value)} /></div>
                <div className="field-stack"><Label htmlFor="account-secret">Секретный ключ</Label><Textarea id="account-secret" placeholder="Вставьте ключ Base32" value={newSecret} onChange={(e) => setNewSecret(e.target.value)} rows={3} /></div>
                {formError && <p className="form-error">{formError}</p>}
                <DialogFooter><Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>Отмена</Button><Button type="submit" disabled={busy}>{busy ? <LoaderCircle className="animate-spin" /> : <Plus />}Сохранить</Button></DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </section>

        <section className="quick-section">
          <Card className="quick-card">
            <div className="quick-icon"><Zap size={19} fill="currentColor" /></div>
            <div className="quick-body">
              <div className="quick-heading"><div><CardTitle>Быстрый код</CardTitle><CardDescription>Вставьте секрет, чтобы мгновенно получить одноразовый код</CardDescription></div><span className="quick-tag">НЕ ЗАПИСЫВАЕТСЯ</span></div>
              <form className="quick-form" onSubmit={generateQuickCode}>
                <Input aria-label="Секретный ключ Base32" placeholder="Например, DJFZ4AQAPY7GOXYMV7VUYX6UUTNPEZNA" value={quickSecret} onChange={(e) => { setQuickSecret(e.target.value); setQuickCode(null); setQuickError(""); quickActive.current = false; void invoke("clear_quick_code").catch(() => undefined); }} />
                <Button type="submit" disabled={!quickSecret.trim()}><Zap size={16} /> Получить код</Button>
              </form>
              {quickError && <p className="form-error quick-error">{quickError}</p>}
              {quickCode && <div className="quick-result"><Separator /><div className="result-line"><div><span className="result-label">ОДНОРАЗОВЫЙ КОД</span><strong className="result-code">{quickCode.code}</strong><span className="result-time">Обновится через {quickCode.remaining} сек.</span></div><div className="quick-actions"><Button variant="outline" onClick={() => void copyCode(quickCode.code, "quick")}>{copied === "quick" ? <Check /> : <Copy />}{copied === "quick" ? "Скопировано" : "Копировать"}</Button><Tooltip><TooltipTrigger asChild><Button variant="ghost" size="icon" aria-label="Скрыть быстрый код" onClick={() => { quickActive.current = false; setQuickCode(null); void invoke("clear_quick_code"); }}><X /></Button></TooltipTrigger><TooltipContent>Скрыть быстрый код</TooltipContent></Tooltip></div></div></div>}
            </div>
          </Card>
        </section>

        <section className="accounts-section">
          <div className="section-heading"><div><h2>Сохранённые аккаунты</h2><p>{accounts.length ? `${accounts.length} ${accounts.length === 1 ? "аккаунт" : accounts.length < 5 ? "аккаунта" : "аккаунтов"}` : "Ваши личные коды"}</p></div><span className="local-note"><LockKeyhole size={13} /> Только на этом устройстве</span></div>
          {accounts.length === 0 ? (
            <Card className="empty-card"><CardContent className="empty-content"><div className="empty-icon"><KeyRound size={22} /></div><h3>Здесь пока пусто</h3><p>Добавьте аккаунт, чтобы ваши коды всегда были под рукой.</p><Button variant="outline" onClick={() => setDialogOpen(true)}><Plus /> Добавить первый аккаунт</Button></CardContent></Card>
          ) : (
            <div className="account-list">
              {accounts.map((account) => {
                const item = codes[account.id];
                return <Card className="account-card" key={account.id}>
                  <div className="account-symbol"><KeyRound size={18} /></div>
                  <div className="account-main"><div className="account-name">{account.name}</div><div className="account-caption">Аутентификатор</div></div>
                  <div className="code-area"><div className="code-value">{item?.code?.match(/.{1,3}/g)?.join(" ") ?? "••• •••"}</div><Progress value={item ? ((30 - item.remaining) / 30) * 100 : 0} className="code-progress" /><span className="countdown">{item?.remaining ?? 30} сек.</span></div>
                  <div className="row-actions">
                    <Tooltip><TooltipTrigger asChild><Button variant="outline" size="icon" aria-label={`Скопировать код ${account.name}`} disabled={!item} onClick={() => item && void copyCode(item.code, account.id)}>{copied === account.id ? <Check /> : <Copy />}</Button></TooltipTrigger><TooltipContent>Скопировать код</TooltipContent></Tooltip>
                    <Dialog>
                      <Tooltip><TooltipTrigger asChild><DialogTrigger asChild><Button variant="ghost" size="icon" aria-label={`Удалить аккаунт ${account.name}`}><Trash2 /></Button></DialogTrigger></TooltipTrigger><TooltipContent>Удалить аккаунт</TooltipContent></Tooltip>
                      <DialogContent><DialogHeader><DialogTitle>Удалить аккаунт?</DialogTitle><DialogDescription>«{account.name}» и его секрет будут удалены с этого компьютера.</DialogDescription></DialogHeader><DialogFooter><DialogClose asChild><Button variant="outline">Отмена</Button></DialogClose><DialogClose asChild><Button variant="destructive" onClick={() => void deleteAccount(account.id)}>Удалить</Button></DialogClose></DialogFooter></DialogContent>
                    </Dialog>
                  </div>
                </Card>;
              })}
            </div>
          )}
        </section>
        {copyError && <p className="form-error copy-error">{copyError}</p>}
        {authError && <Alert variant="destructive" className="runtime-alert"><ShieldAlert /><AlertTitle>Ошибка хранилища</AlertTitle><AlertDescription>{authError}</AlertDescription></Alert>}
        <footer className="app-footer"><span><LockKeyhole size={13} /> Зашифровано Windows DPAPI</span><span>Коды обновляются каждые 30 секунд</span></footer>
      </main>
    </TooltipProvider>
  );
}

export default App;
