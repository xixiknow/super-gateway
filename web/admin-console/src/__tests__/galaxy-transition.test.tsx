import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { GalaxyTransition } from "../GalaxyTransition";

afterEach(cleanup);

describe("galaxy loading transition", () => {
  it("is decorative and canvas-based", () => {
    document.documentElement.dataset.theme = "dark";
    const { container } = render(<GalaxyTransition />);
    const element = container.querySelector(".galaxy-transition");

    expect(element).toHaveAttribute("aria-hidden", "true");
    expect(element?.querySelector("canvas.galaxy-canvas")).toBeInTheDocument();
    expect(element?.querySelector(".galaxy-river")).not.toBeInTheDocument();
  });

  it("keeps breathing during the boot/loading phase instead of playing once", () => {
    document.documentElement.dataset.theme = "dark";
    const { container } = render(<GalaxyTransition hold />);
    const element = container.querySelector(".galaxy-transition");

    expect(element).toHaveClass("hold");
    expect(element).toHaveAttribute("aria-hidden", "true");
  });

  it("is skipped in the light theme", () => {
    document.documentElement.dataset.theme = "light";
    const { container } = render(<GalaxyTransition />);

    expect(container.querySelector(".galaxy-transition")).not.toBeInTheDocument();
  });
});
