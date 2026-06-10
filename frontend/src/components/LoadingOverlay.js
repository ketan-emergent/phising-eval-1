export default function LoadingOverlay({ visible }) {
  if (!visible) return null;
  return (
    <div className="fixed inset-0 bg-background/70 z-30 flex items-center justify-center pointer-events-none" data-testid="loading-overlay">
      <div className="bg-card border border-border rounded-sm px-10 py-6 text-center">
        <div className="w-7 h-7 border-2 border-border border-t-primary rounded-full animate-spin mx-auto mb-3" />
        <span className="text-sm text-muted-foreground font-mono">Loading from BigQuery...</span>
      </div>
    </div>
  );
}
