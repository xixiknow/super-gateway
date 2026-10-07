import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/inter/700.css";
import "@fontsource/geist-mono/400.css";
import "@fontsource/geist-mono/500.css";
import "./fresh-garden-ui.css";
import "./app.css";
import { App } from "./App";
import { FeedbackProvider } from "./feedback";
import { I18nProvider } from "./i18n";
import { ThemeProvider } from "./theme";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 15_000, refetchOnWindowFocus: false },
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <I18nProvider>
      <ThemeProvider>
        <FeedbackProvider>
          <QueryClientProvider client={queryClient}>
            <BrowserRouter basename="/admin">
              <App />
            </BrowserRouter>
          </QueryClientProvider>
        </FeedbackProvider>
      </ThemeProvider>
    </I18nProvider>
  </React.StrictMode>,
);
