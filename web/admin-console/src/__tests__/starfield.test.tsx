import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Starfield } from "../Starfield";

afterEach(cleanup);

describe("login starfield", () => {
  it("is decorative and canvas-based", () => {
    document.documentElement.dataset.theme = "dark";
    const { container } = render(<Starfield />);
    const element = container.querySelector(".login-starfield");

    expect(element).toHaveAttribute("aria-hidden", "true");
    expect(element?.querySelector("canvas")).toBeInTheDocument();
    expect(element?.textContent).toBe("");
  });

  it("is skipped in the light theme", () => {
    document.documentElement.dataset.theme = "light";
    const { container } = render(<Starfield />);

    expect(container.querySelector(".login-starfield")).not.toBeInTheDocument();
  });
});
