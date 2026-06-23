import { createContext, useContext, useState } from "react";

interface Prefill {
  target?: string;
  scanType?: string;
}

interface NewScanCtx {
  open: boolean;
  prefill: Prefill | null;
  openNewScan: (prefill?: Prefill) => void;
  close: () => void;
}

const NewScanContext = createContext<NewScanCtx | null>(null);

export function NewScanProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const [prefill, setPrefill] = useState<Prefill | null>(null);
  return (
    <NewScanContext.Provider
      value={{
        open,
        prefill,
        openNewScan: (p?: Prefill) => { setPrefill(p ?? null); setOpen(true); },
        close: () => { setOpen(false); setPrefill(null); },
      }}
    >
      {children}
    </NewScanContext.Provider>
  );
}

export function useNewScan(): NewScanCtx {
  const ctx = useContext(NewScanContext);
  if (!ctx) throw new Error("useNewScan must be used within a NewScanProvider");
  return ctx;
}
