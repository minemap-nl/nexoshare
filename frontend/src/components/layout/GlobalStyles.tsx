export function GlobalStyles() {
    return (
        <style>{`
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    @keyframes slideUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes scaleIn { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
    @keyframes slideInRight { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    .anim-fade { animation: fadeIn 0.3s ease-out forwards; }
    .anim-slide { animation: slideUp 0.4s ease-out forwards; }
    .anim-scale { animation: scaleIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
    .anim-toast { animation: slideInRight 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
    .btn-press:active { transform: scale(0.96); }
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: #09090b; }
    ::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #0d9488; }
    
    /* Mobile touch improvements */
    @media (max-width: 768px) {
      * { -webkit-tap-highlight-color: transparent; }
      body { overflow-x: hidden; }
    }
  `}</style>
    );
}
