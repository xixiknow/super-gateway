import { useEffect, useRef } from "react";

type RGB = readonly [number, number, number];

interface StarParticle {
  u: number;
  offset: number;
  size: number;
  alpha: number;
  cluster: number;
  phase: number;
  color: RGB;
  flare: boolean;
}

interface DustCloud {
  u: number;
  offset: number;
  radius: number;
  alpha: number;
  cluster: number;
  colorIndex: number;
}

interface SkyStar {
  x: number;
  y: number;
  size: number;
  alpha: number;
  speed: number;
}

interface GalaxyTextureCache {
  width: number;
  height: number;
  ratio: number;
  texture: HTMLCanvasElement;
}

let galaxyTextureCache: GalaxyTextureCache | null = null;

const STAR_COLORS: RGB[] = [
  [235, 242, 255],
  [199, 210, 254],
  [165, 243, 252],
  [224, 231, 255],
  [255, 244, 214],
];

const DUST_COLORS: RGB[] = [
  [79, 70, 229],
  [14, 165, 233],
  [125, 211, 252],
  [67, 56, 202],
];

function seededRandom(seed: number): () => number {
  let value = seed >>> 0;
  return () => {
    value += 0x6D2B79F5;
    let mixed = value;
    mixed = Math.imul(mixed ^ mixed >>> 15, mixed | 1);
    mixed ^= mixed + Math.imul(mixed ^ mixed >>> 7, mixed | 61);
    return ((mixed ^ mixed >>> 14) >>> 0) / 4294967296;
  };
}

function gaussian(random: () => number): number {
  const first = Math.max(random(), Number.EPSILON);
  return Math.cos(2 * Math.PI * random()) * Math.sqrt(-2 * Math.log(first));
}

const CORE_LAYERS: ReadonlyArray<{ scale: number; alpha: number; color: RGB }> = [
  { scale: 1, alpha: .16, color: [79, 70, 229] },
  { scale: .55, alpha: .34, color: [125, 211, 252] },
  { scale: .26, alpha: .5, color: [224, 242, 254] },
  { scale: .1, alpha: .95, color: [255, 255, 255] },
];

function makeStars(count: number, random: () => number): StarParticle[] {
  const stars = Array.from({ length: count }, () => {
    const bright = random() < .055;
    const core = random() < .58;
    return {
      u: random(),
      offset: Math.max(-3.1, Math.min(3.1, gaussian(random) * (core ? .33 : 1))),
      size: bright ? 1.7 + random() * 1.5 : .55 + random() * 1.25,
      alpha: bright ? .92 + random() * .08 : .6 + random() * .4,
      cluster: random(),
      phase: random() * Math.PI * 2,
      color: STAR_COLORS[Math.floor(random() * STAR_COLORS.length)],
      flare: bright && random() < .58,
    };
  });
  // 中心核星簇:在 u≈0.5 附近聚拢一小簇亮星(cluster=0 永不稀疏化),锚定"由中心点发散"的视觉焦点
  for (let index = 0; index < Math.round(count * .02); index++) {
    stars.push({
      u: Math.max(.32, Math.min(.68, .5 + gaussian(random) * .045)),
      offset: Math.max(-1.2, Math.min(1.2, gaussian(random) * .2)),
      size: .9 + random() * 1.5,
      alpha: .65 + random() * .35,
      cluster: 0,
      phase: random() * Math.PI * 2,
      color: STAR_COLORS[Math.floor(random() * STAR_COLORS.length)],
      flare: random() < .25,
    });
  }
  return stars;
}

function makeDust(count: number, random: () => number): DustCloud[] {
  return Array.from({ length: count }, () => ({
    u: random(),
    offset: Math.max(-2.1, Math.min(2.1, gaussian(random) * .72)),
    radius: 22 + random() * 68,
    alpha: .055 + random() * .085,
    cluster: random(),
    colorIndex: Math.floor(random() * DUST_COLORS.length),
  }));
}

function makeSky(count: number, random: () => number): SkyStar[] {
  return Array.from({ length: count }, () => ({
    x: random(),
    y: random(),
    size: .35 + random() * .9,
    alpha: .08 + random() * .24,
    speed: .002 + random() * .008,
  }));
}

const smoothstep = (start: number, end: number, value: number): number => {
  const progress = Math.max(0, Math.min(1, (value - start) / (end - start)));
  return progress * progress * (3 - 2 * progress);
};

function centerLine(u: number, width: number, height: number): [number, number] {
  // 屏幕正中的一条水平星河:宽度方向填满,高度方向只做轻微波浪防止死板
  const x = u * width;
  const wave = Math.sin(u * Math.PI) * height * 0.012 + Math.sin(u * Math.PI * 3) * height * 0.005;
  return [x, height * 0.5 + wave];
}

function densityAt(u: number): number {
  const broad = .5 + .5 * Math.sin(u * 25.7 + .8);
  const fine = .5 + .5 * Math.sin(u * 61.3 - .4);
  return .34 + .66 * Math.pow(broad * .68 + fine * .32, 1.25);
}

function makeDustSprites(): HTMLCanvasElement[] {
  return DUST_COLORS.map(([red, green, blue]) => {
    const sprite = document.createElement("canvas");
    sprite.width = 96;
    sprite.height = 96;
    const context = sprite.getContext("2d");
    if (!context) return sprite;
    const gradient = context.createRadialGradient(48, 48, 0, 48, 48, 48);
    gradient.addColorStop(0, `rgba(${red},${green},${blue},.9)`);
    gradient.addColorStop(.38, `rgba(${red},${green},${blue},.38)`);
    gradient.addColorStop(1, `rgba(${red},${green},${blue},0)`);
    context.fillStyle = gradient;
    context.fillRect(0, 0, 96, 96);
    return sprite;
  });
}

function makeStarSprites(): HTMLCanvasElement[] {
  return STAR_COLORS.map(([red, green, blue]) => {
    const sprite = document.createElement("canvas");
    sprite.width = 32;
    sprite.height = 32;
    const context = sprite.getContext("2d");
    if (!context) return sprite;
    const gradient = context.createRadialGradient(16, 16, 0, 16, 16, 16);
    gradient.addColorStop(0, `rgba(${red},${green},${blue},1)`);
    gradient.addColorStop(.13, `rgba(${red},${green},${blue},.92)`);
    gradient.addColorStop(.46, `rgba(${red},${green},${blue},.2)`);
    gradient.addColorStop(1, `rgba(${red},${green},${blue},0)`);
    context.fillStyle = gradient;
    context.fillRect(0, 0, 32, 32);
    return sprite;
  });
}

/**
 * 星河带厚度/alpha:以 u=0.5 为中心,向两端逐步收细(sin(π·u)^p,高次幂让
 * 亮部集中在中心点附近,两端拖出细长尾迹);u=0/1 时趋近于 0,配合 density
 * 函数形成两端稀疏的银河系两臂
 */
function bandShape(u: number, base: number, power: number): number {
  return base * Math.pow(Math.max(0, Math.sin(Math.PI * u)), power);
}

/**
 * 银河亮核:屏幕正中心的白热核心 + 分层压扁光晕(沿星河盘面压成椭圆),
 * 外加一条沿带穿过中心的水平亮脊,作为整条星河发散的原点
 */
function drawGalacticCore(context: CanvasRenderingContext2D, width: number, height: number) {
  const [cx, cy] = centerLine(.5, width, height);
  const radius = Math.min(width * .11, height * .8);
  context.save();
  context.translate(cx, cy);
  context.scale(1, .36);
  for (const layer of CORE_LAYERS) {
    const r = radius * layer.scale;
    const [red, green, blue] = layer.color;
    const gradient = context.createRadialGradient(0, 0, 0, 0, 0, r);
    gradient.addColorStop(0, `rgba(${red},${green},${blue},${layer.alpha})`);
    gradient.addColorStop(.55, `rgba(${red},${green},${blue},${(layer.alpha * .32).toFixed(3)})`);
    gradient.addColorStop(1, `rgba(${red},${green},${blue},0)`);
    context.fillStyle = gradient;
    context.fillRect(-r, -r, r * 2, r * 2);
  }
  context.restore();
  const streak = width * .21;
  const shine = context.createLinearGradient(cx - streak, 0, cx + streak, 0);
  shine.addColorStop(0, "rgba(191,219,254,0)");
  shine.addColorStop(.5, "rgba(240,246,255,.5)");
  shine.addColorStop(1, "rgba(191,219,254,0)");
  context.fillStyle = shine;
  context.fillRect(cx - streak, cy - 1, streak * 2, 2);
}

function renderGalaxyTexture(
  texture: HTMLCanvasElement,
  context: CanvasRenderingContext2D,
  width: number,
  height: number,
  ratio: number,
  stars: StarParticle[],
  dust: DustCloud[],
  dustSprites: HTMLCanvasElement[],
  starSprites: HTMLCanvasElement[],
) {
  texture.width = Math.round(width * ratio);
  texture.height = Math.round(height * ratio);
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  context.globalCompositeOperation = "lighter";
  context.globalAlpha = 1;

  for (const cloud of dust) {
    if (cloud.cluster > densityAt(cloud.u)) continue;
    const [x, centerY] = centerLine(cloud.u, width, height);
    const thickness = bandShape(cloud.u, height * 0.19, 2.3) * (0.9 + 0.1 * Math.sin(cloud.u * 10.7));
    const y = centerY + cloud.offset * thickness;
    const edgeAlpha = Math.pow(Math.max(0, Math.sin(Math.PI * cloud.u)), 1.8);
    context.globalAlpha = cloud.alpha * edgeAlpha;
    context.drawImage(dustSprites[cloud.colorIndex], x - cloud.radius, y - cloud.radius, cloud.radius * 2, cloud.radius * 2);
  }

  for (const star of stars) {
    const gapAlpha = star.cluster > densityAt(star.u) && !star.flare ? .08 : 1;
    const [x, centerY] = centerLine(star.u, width, height);
    const thickness = bandShape(star.u, height * 0.18, 2.3) * (0.9 + 0.1 * Math.sin(star.u * 11.4 + .7));
    const y = centerY + star.offset * thickness;
    const edgeFade = Math.pow(Math.max(0, Math.sin(Math.PI * star.u)), 1.5);
    const alpha = star.alpha * (.78 + .22 * Math.sin(star.phase)) * edgeFade * gapAlpha;
    const [red, green, blue] = star.color;
    context.globalAlpha = alpha;
    context.fillStyle = `rgb(${red},${green},${blue})`;
    if (star.size > 1.9) {
      const glowSize = star.size * 8;
      const spriteIndex = STAR_COLORS.indexOf(star.color);
      context.drawImage(starSprites[spriteIndex], x - glowSize / 2, y - glowSize / 2, glowSize, glowSize);
      context.globalAlpha = alpha;
      context.beginPath();
      context.arc(x, y, star.size * .62, 0, Math.PI * 2);
      context.fill();
      if (star.flare) {
        context.globalAlpha = alpha * .48;
        context.fillRect(x - star.size * 4.8, y - .35, star.size * 9.6, .7);
        context.fillRect(x - .35, y - star.size * 3.6, .7, star.size * 7.2);
      }
    } else {
      context.fillRect(x, y, star.size, star.size);
    }
  }
  context.globalAlpha = 1;
  drawGalacticCore(context, width, height);
  context.globalAlpha = 1;
}

export function GalaxyTransition({ compact = false, hold = false }: { compact?: boolean; hold?: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || navigator.userAgent.includes("jsdom")) return;
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;
    const context = canvas.getContext("2d");
    if (!context) return;

    const duration = compact ? 880 : 1120;
    const sky = makeSky(window.innerWidth < 720 ? 70 : 110, seededRandom(0x17a4f02b));
    let texture: HTMLCanvasElement | null = null;
    let width = 0;
    let height = 0;
    let frame = 0;
    let start = 0;

    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 1.35);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      if (galaxyTextureCache && galaxyTextureCache.width === width && galaxyTextureCache.height === height && galaxyTextureCache.ratio === ratio) {
        texture = galaxyTextureCache.texture;
        return;
      }
      texture = document.createElement("canvas");
      const textureContext = texture.getContext("2d");
      if (!textureContext) return;
      const random = seededRandom(0x5a17c9e3);
      const stars = makeStars(width < 720 ? 460 : 860, random);
      const dust = makeDust(width < 720 ? 34 : 56, random);
      renderGalaxyTexture(texture, textureContext, width, height, ratio, stars, dust, makeDustSprites(), makeStarSprites());
      galaxyTextureCache = { width, height, ratio, texture };
    };

    const draw = (timestamp: number) => {
      if (!texture) return;
      if (!start) start = timestamp;
      const elapsed = timestamp - start;
      // hold(整体加载):入场后常驻,整体透明度/位置缓慢呼吸,直到阶段切换被卸载;
      // 一次性(路由切换):1120/880ms 内完成入场-驻留-淡出
      let visibility: number;
      let bob: number;
      let keepGoing = true;
      if (hold) {
        const arrival = smoothstep(0, 620, elapsed);
        visibility = arrival * (0.9 + 0.1 * Math.sin(elapsed * 0.0015));
        bob = Math.sin(elapsed * 0.0008) * 4;
      } else {
        const progress = Math.min(1, elapsed / duration);
        const arrival = smoothstep(0, .16, progress);
        const departure = 1 - smoothstep(.62, 1, progress);
        visibility = Math.min(arrival, departure);
        bob = Math.sin(progress * Math.PI * 2) * 3;
        keepGoing = progress < 1;
        canvas.dataset.galaxyProgress = progress.toFixed(3);
      }
      context.clearRect(0, 0, width, height);
      context.globalCompositeOperation = "source-over";
      for (const star of sky) {
        context.globalAlpha = star.alpha * visibility;
        context.fillStyle = "#dbeafe";
        context.fillRect((star.x * width + elapsed * star.speed) % width, star.y * height, star.size, star.size);
      }

      context.save();
      context.translate(width / 2, height / 2 + bob);
      const scale = .985 + visibility * .025;
      context.scale(scale, scale);
      context.globalAlpha = visibility;
      context.globalCompositeOperation = "lighter";
      context.drawImage(texture, -width / 2, -height / 2, width, height);
      context.restore();
      context.globalAlpha = 1;
      canvas.dataset.galaxyReady = "true";

      if (keepGoing) frame = window.requestAnimationFrame(draw);
    };

    resize();
    window.addEventListener("resize", resize);
    frame = window.requestAnimationFrame(draw);
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
    };
  }, [compact, hold]);

  return (
    <div className={`galaxy-transition${compact ? " compact" : ""}${hold ? " hold" : ""}`} aria-hidden="true">
      <canvas className="galaxy-canvas" ref={canvasRef} />
    </div>
  );
}
