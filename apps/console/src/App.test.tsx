import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import App from "./App";

describe("KubeAthrix console", () => {
  it("renders the operator dashboard with seeded risk metrics", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("api offline"))));
    render(<App />);

    expect(await screen.findByText("KubeAthrix")).toBeInTheDocument();
    expect(await screen.findByText("Correlated cluster risk")).toBeInTheDocument();
    expect(await screen.findByText("Open critical")).toBeInTheDocument();
  });

  it("creates a typed remediation plan from the findings workflow", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("api offline"))));
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: /Findings/i }));
    await user.click(await screen.findByRole("button", { name: /Generate typed plan/i }));

    expect(await screen.findByText("Find, explain, fix, verify, prove")).toBeInTheDocument();
    expect(await screen.findByText(/Approval required|Deterministic/)).toBeInTheDocument();
  });
});
