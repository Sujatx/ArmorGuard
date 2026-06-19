import React from "react";

export default function Home() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-teal-500 selection:text-slate-900">
      {/* Premium Header */}
      <header className="border-b border-slate-900 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50 px-6 py-4 flex justify-between items-center">
        <div className="flex items-center gap-3">
          <span className="h-4 w-4 rounded-full bg-teal-500 animate-pulse shadow-[0_0_10px_#14b8a6]"></span>
          <h1 className="text-xl font-bold tracking-wider text-slate-200">
            ARMOR<span className="text-teal-400 font-extrabold">GUARD</span>
          </h1>
          <span className="text-xs bg-slate-900 border border-slate-800 text-teal-400 px-2 py-0.5 rounded font-mono uppercase tracking-widest">
            v1.0.0-dev
          </span>
        </div>
        <div className="text-xs font-mono text-slate-400">
          Governance Dashboard Active
        </div>
      </header>

      {/* Hero / Main Area */}
      <main className="flex-1 flex flex-col items-center justify-center p-6 md:p-12 max-w-4xl mx-auto w-full text-center">
        <div className="relative group mb-8">
          <div className="absolute -inset-0.5 bg-gradient-to-r from-teal-500 to-emerald-500 rounded-full blur opacity-30 group-hover:opacity-60 transition duration-1000"></div>
          <div className="relative bg-slate-950 px-8 py-8 rounded-full border border-slate-800 flex items-center justify-center">
            <svg className="w-16 h-16 text-teal-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
            </svg>
          </div>
        </div>

        <h2 className="text-3xl md:text-5xl font-extrabold tracking-tight text-white mb-4 bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
          Autonomous AI Pentesting
        </h2>
        <p className="text-lg text-slate-400 max-w-2xl mb-8 leading-relaxed">
          ArmorGuard is an autonomous AI agent that proactively audits target environments, running tools governed dynamically in real-time by the ArmorIQ SDK.
        </p>

        {/* Action Panel / Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full text-left mb-12">
          <div className="p-6 bg-slate-900/50 rounded-xl border border-slate-900 hover:border-slate-800 transition duration-300">
            <h3 className="text-sm font-semibold text-teal-400 font-mono mb-2">01 / AUTONOMOUS AUDITING</h3>
            <p className="text-sm text-slate-400">PydanticAI agent reasons about open ports, detects vulnerabilities, and logs forensics.</p>
          </div>
          <div className="p-6 bg-slate-900/50 rounded-xl border border-slate-900 hover:border-slate-800 transition duration-300">
            <h3 className="text-sm font-semibold text-teal-400 font-mono mb-2">02 / REAL-TIME GOVERNANCE</h3>
            <p className="text-sm text-slate-400">ArmorIQ intercepts agent drift and prompt injections, blocking unauthorized actions dynamically.</p>
          </div>
          <div className="p-6 bg-slate-900/50 rounded-xl border border-slate-900 hover:border-slate-800 transition duration-300">
            <h3 className="text-sm font-semibold text-teal-400 font-mono mb-2">03 / VERIFIED COMPLIANCE</h3>
            <p className="text-sm text-slate-400">Consent checks, structured vulnerability logs, and professional PDF reports built-in.</p>
          </div>
        </div>

        {/* Mini Console Status */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 w-full text-left font-mono text-sm max-w-2xl shadow-2xl">
          <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
            <span className="w-3 h-3 rounded-full bg-red-500"></span>
            <span className="w-3 h-3 rounded-full bg-yellow-500"></span>
            <span className="w-3 h-3 rounded-full bg-green-500"></span>
            <span className="text-xs text-slate-500 ml-2">armorguard-scaffold-boot.log</span>
          </div>
          <div className="space-y-1.5 text-slate-300">
            <p className="text-slate-500">&gt; npm run dev</p>
            <p className="text-teal-400">✓ Ready in 294ms</p>
            <p className="text-slate-400">○ Local: http://localhost:3000</p>
            <p className="text-slate-400">○ Env loaded: SUPABASE, ARMORIQ, LLM_PROVIDER</p>
            <p className="text-emerald-400">✓ FastAPI backend bound successfully at port 8000</p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 py-6 text-center text-xs text-slate-600 font-mono mt-auto">
        &copy; {new Date().getFullYear()} ArmorGuard Security Systems. Built for NeuroX 2026.
      </footer>
    </div>
  );
}
