import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Starfield } from "../Starfield";

afterEach(cleanup);

describe("login starfield", () => {
  it("is decorative and canvas-based", () => {
    const { container } = render(<Starfield />);
    const element = container.querySelector(".login-starfield");

    expect(element).toHaveAttribute("aria-hidden", "true");
    expect(element?.querySelector("canvas")).toBeInTheDocument();
    expect(element?.textContent).toBe("");
  });
});
