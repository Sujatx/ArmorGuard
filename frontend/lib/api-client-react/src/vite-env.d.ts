// Augment the global ImportMeta so import.meta.env is typed within this library.
// The main app uses vite/client for this; the lib tsconfig is minimal so we declare it here.
interface ImportMeta {
  readonly env: Record<string, string | undefined>;
}
