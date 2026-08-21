# Verdikt frontend

Vite + React + TypeScript + TanStack Query + React Router + Tailwind CSS. See the
root `README.md` for how to run this alongside the backend, and
`app/schemas/*.py` in `backend/` as the source of truth for `src/api/types.ts`.

```bash
npm install
npm run dev      # http://localhost:5173, expects the backend at VITE_API_BASE_URL
npm run build    # tsc -b && vite build
```

`src/api/client.ts` is a hand-written typed fetch client (no OpenAPI codegen) — every
backend endpoint it wraps is grouped by resource and mirrors the route paths in
`backend/app/api/routes/` exactly.
