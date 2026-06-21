import { createContext, useContext, useState } from "react";

interface NewScanCtx {
  open: boolean;
  openNewScan: () => void;
  close: () => void;
}

const NewScanContext = createContext<NewScanCtx | null>(null);

export function NewScanProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <NewScanContext.Provider
      value={{ open, openNewScan: () => setOpen(true), close: () => setOpen(false) }}
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
