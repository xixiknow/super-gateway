import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { GalaxyTransition } from "../GalaxyTransition";

afterEach(cleanup);

describe("galaxy loading transition", () => {
  it("is decorative and canvas-based", () => {
    const { container } = render(<GalaxyTransition />);
    const element = container.querySelector(".galaxy-transition");

    expect(element).toHaveAttribute("aria-hidden", "true");
    expect(element?.querySelector("canvas.galaxy-canvas")).toBeInTheDocument();
    expect(element?.querySelector(".galaxy-river")).not.toBeInTheDocument();
  });

  it("keeps breathing during the boot/loading phase instead of playing once", () => {
    const { container } = render(<GalaxyTransition hold />);
    const element = container.querySelector(".galaxy-transition");

    expect(element).toHaveClass("hold");
    expect(element).toHaveAttribute("aria-hidden", "true");
  });
});
