import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "./tower.css";
import { ApiError, useToken } from "./lib/api";
import { Shell } from "./components/Shell";
import { SignIn } from "./pages/SignIn";
import { Posture } from "./pages/Posture";
import { Agents } from "./pages/Agents";
import { Agent } from "./pages/Agent";
import { FindingsPage } from "./pages/FindingsPage";
import { Activity } from "./pages/Activity";
import { Guardrails } from "./pages/Guardrails";
import { Waivers } from "./pages/Waivers";
import { Inbox } from "./pages/Inbox";
import { Ask } from "./pages/Ask";
import { Fleet } from "./pages/Fleet";
import { Revocations } from "./pages/Revocations";
import { Journal } from "./pages/Journal";
import { Spend } from "./pages/Spend";
import { NotFound } from "./pages/NotFound";

const client = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: true,
      staleTime: 5_000,
      retry: (count, error) => !(error instanceof ApiError && error.status < 500) && count < 2,
    },
  },
});

const router = createBrowserRouter(
  [
    {
      element: <Shell />,
      children: [
        { index: true, element: <Posture /> },
        { path: "agents", element: <Agents /> },
        { path: "agents/:key", element: <Agent /> },
        { path: "findings", element: <FindingsPage /> },
        { path: "activity", element: <Activity /> },
        { path: "spend", element: <Spend /> },
        { path: "guardrails", element: <Guardrails /> },
        { path: "waivers", element: <Waivers /> },
        { path: "inbox", element: <Inbox /> },
        { path: "ask", element: <Ask /> },
        { path: "fleet", element: <Fleet /> },
        { path: "revocations", element: <Revocations /> },
        { path: "journal", element: <Journal /> },
        { path: "*", element: <NotFound /> },
      ],
    },
  ],
  { basename: "/tower" },
);

function App() {
  const token = useToken();
  return token ? <RouterProvider router={router} /> : <SignIn />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
