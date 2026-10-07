import { useEffect, useRef } from "react";
import { useTheme } from "./theme";

type RGB = readonly [number, number, number];

interface Star {
  x: number;
  y: number;
  size: number;
  alpha: number;
  phase: number;
  speed: number;
  driftX: number;
  driftY: number;
  color: number;
  glow: boolean;
  flare: boolean;
}

interface SwellWave {
  k: number;      // 波数(弧度/波光格)
  ct: number;     // cos(方向角)
  st: number;     // sin(方向角)
  ampK: number;   // 振幅 × 波数
  omega: number;  // 角频率(弧度/ms)
}

const STAR_COLORS: RGB[] = [
  [235, 242, 255],  // 白蓝
  [199, 210, 254],  // 靛蓝
  [165, 243, 252],  // 青
  [224, 231, 255],  // 淡蓝
  [255, 244, 214],  // 暖白
  [255, 214, 150],  // 暖金
  [244, 180, 210],  // 玫瑰粉
  [196, 165, 255],  // 紫罗兰
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

const clamp = (min: number, max: number, value: number): number => Math.max(min, Math.min(max, value));

const gauss = (random: () => number): number =>
  Math.cos(2 * Math.PI * random()) * Math.sqrt(-2 * Math.log(Math.max(random(), Number.EPSILON)));

function makeGlowSprite([red, green, blue]: RGB): HTMLCanvasElement {
  const sprite = document.createElement("canvas");
  sprite.width = 32;
  sprite.height = 32;
  const context = sprite.getContext("2d");
  if (context) {
    const gradient = context.createRadialGradient(16, 16, 0, 16, 16, 16);
    gradient.addColorStop(0, `rgba(${red},${green},${blue},1)`);
    gradient.addColorStop(.2, `rgba(${red},${green},${blue},.5)`);
    gradient.addColorStop(1, `rgba(${red},${green},${blue},0)`);
    context.fillStyle = gradient;
    context.fillRect(0, 0, 32, 32);
  }
  return sprite;
}

function makeStars(count: number, random: () => number, width: number, height: number): Star[] {
  return Array.from({ length: count }, () => {
    const glow = random() < .1;
    return {
      x: random() * width,
      y: random() * height,
      size: glow ? 1.6 + random() * 1.5 : .4 + random() * 1.2,
      alpha: .18 + random() * .62,
      phase: random() * Math.PI * 2,
      speed: .0004 + random() * .0012,
      driftX: (random() - .5) * .0016,
      driftY: (random() - .5) * .001,
      color: Math.floor(random() * STAR_COLORS.length),
      glow,
      flare: glow && random() < .2,   // 最亮的一小撮带十字光芒
    };
  });
}

/* 背景层:深空渐变 + 极淡星云 + 斜贯星尘带,resize 时静态烘焙一次 */
function buildBackground(width: number, height: number, ratio: number): HTMLCanvasElement {
  const bg = document.createElement("canvas");
  bg.width = Math.round(width * ratio);
  bg.height = Math.round(height * ratio);
  const context = bg.getContext("2d");
  if (!context) return bg;
  context.setTransform(ratio, 0, 0, ratio, 0, 0);

  const gradient = context.createLinearGradient(0, 0, 0, height);
  gradient.addColorStop(0, "#030409");
  gradient.addColorStop(.55, "#060a1c");
  gradient.addColorStop(1, "#0a0e28");
  context.fillStyle = gradient;
  context.fillRect(0, 0, width, height);

  const random = seededRandom(0x3f9d27b1);
  const NEBULAS: RGB[] = [[79, 70, 229], [14, 165, 233], [219, 120, 170], [103, 65, 198]];
  for (const [nr, ng, nb] of NEBULAS) {
    const cx = width * (.12 + random() * .76);
    const cy = height * (.1 + random() * .7);
    const r = Math.max(width, height) * (.22 + random() * .2);
    const g = context.createRadialGradient(cx, cy, 0, cx, cy, r);
    g.addColorStop(0, `rgba(${nr},${ng},${nb},${(.05 + random() * .05).toFixed(3)})`);
    g.addColorStop(1, `rgba(${nr},${ng},${nb},0)`);
    context.fillStyle = g;
    context.fillRect(cx - r, cy - r, r * 2, r * 2);
  }

  context.globalCompositeOperation = "lighter";
  for (let i = 0; i < 800; i++) {
    const u = random();
    const bx = u * width;
    const by = height * .42 + (u - .5) * height * .32 + gauss(random) * height * .075;
    if (by < 0 || by > height) continue;
    const [r, g, b] = STAR_COLORS[Math.floor(random() * STAR_COLORS.length)];
    context.globalAlpha = .13 + random() * .3;
    context.fillStyle = `rgb(${r},${g},${b})`;
    const s = .4 + random() * .9;
    context.fillRect(bx, by, s, s);
  }
  context.globalAlpha = 1;
  context.globalCompositeOperation = "source-over";
  return bg;
}

/* 全局平缓周期行波:三列不同方向/波长/周期的平面波解析叠加,
   波面梯度驱动波光层与星光折射,无任何随机事件 */
const SCALE = 2;          // 波光层分辨率 = 屏幕 / 2
const REFRACT = .5;       // 星光折射强度(像素 / 行波梯度)

const SWELL_WAVES: SwellWave[] = [
  { deg: 15, lambda: 520, amp: 170, period: 9000 },
  { deg: -40, lambda: 340, amp: 110, period: 7000 },
  { deg: 70, lambda: 760, amp: 200, period: 13000 },
].map((wave) => {
  const theta = (wave.deg * Math.PI) / 180;
  const k = (2 * Math.PI) / (wave.lambda / SCALE);
  return { k, ct: Math.cos(theta), st: Math.sin(theta), ampK: wave.amp * k, omega: (2 * Math.PI) / wave.period };
});

function ambientGradient(bx: number, by: number, t: number): { gx: number; gy: number } {
  let gx = 0, gy = 0;
  for (const w of SWELL_WAVES) {
    const c = Math.cos(w.k * (bx * w.ct + by * w.st) - w.omega * t) * w.ampK;
    gx += c * w.ct;
    gy += c * w.st;
  }
  return { gx, gy };
}

/**
 * 登录页常驻背景:星闪烁星空 + 平缓周期水波。
 * 纯装饰(aria-hidden / pointer-events:none),不拦截任何交互;
 * jsdom 下不启动,prefers-reduced-motion 下只画一帧静态画面。
 */
export function Starfield() {
  const { theme } = useTheme();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (theme !== "dark") return;
    const canvas = canvasRef.current;
    if (!canvas || navigator.userAgent.includes("jsdom")) return;
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    const context = canvas.getContext("2d");
    if (!context) return;

    const starSprites = STAR_COLORS.map(makeGlowSprite);
    let stars: Star[] = [];
    let bg: HTMLCanvasElement | null = null;
    let sheen: HTMLCanvasElement | null = null;
    let sheenContext: CanvasRenderingContext2D | null = null;
    let sheenPixels: ImageData | null = null;
    let bw = 0, bh = 0;
    let width = 0, height = 0;
    let frame = 0;
    let start = 0;

    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
      width = canvas.clientWidth || window.innerWidth;
      height = canvas.clientHeight || window.innerHeight;
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);

      bw = Math.max(8, Math.ceil(width / SCALE));
      bh = Math.max(8, Math.ceil(height / SCALE));
      sheen = document.createElement("canvas");
      sheen.width = bw;
      sheen.height = bh;
      sheenContext = sheen.getContext("2d");
      sheenPixels = sheenContext ? sheenContext.createImageData(bw, bh) : null;

      bg = buildBackground(width, height, ratio);
      stars = makeStars(Math.round(clamp(260, 620, (width * height) / 4200)), seededRandom(0x5a7f1e3d), width, height);
    };

    // 波光层:行波梯度 → 蓝白镜面高光,波谷轻微压暗
    const renderSheen = (t: number) => {
      if (!sheenContext || !sheenPixels) return;
      const data = sheenPixels.data;
      for (let y = 1; y < bh - 1; y++) {
        const row = y * bw;
        // 行波相位按行初始化、逐格旋转推进(免逐格三角调用)
        const waves = SWELL_WAVES.map((w) => {
          const phase0 = w.k * (w.ct + y * w.st) - w.omega * t;
          return {
            cos: Math.cos(phase0), sin: Math.sin(phase0),
            cosD: Math.cos(w.k * w.ct), sinD: Math.sin(w.k * w.ct),
            ct: w.ct, st: w.st, ampK: w.ampK,
          };
        });
        for (let x = 1; x < bw - 1; x++) {
          const i = row + x;
          let gx = 0, gy = 0;
          for (const w of waves) {
            const c = w.cos * w.ampK;
            gx += c * w.ct;
            gy += c * w.st;
            const nc = w.cos * w.cosD - w.sin * w.sinD;  // φ += k·cosθ
            w.sin = w.sin * w.cosD + w.cos * w.sinD;
            w.cos = nc;
          }
          const spec = gx * -.6 + gy * -.85;      // 虚拟光源(左上)
          const o = i * 4;
          if (spec > 0) {
            data[o] = 150; data[o + 1] = 205; data[o + 2] = 255;
            data[o + 3] = clamp(0, 130, spec * 4.2);
          } else {
            data[o] = 8; data[o + 1] = 12; data[o + 2] = 30;
            data[o + 3] = clamp(0, 76, -spec * 2.6);
          }
        }
      }
      sheenContext.putImageData(sheenPixels, 0, 0);
    };

    const drawStars = (t: number, refract: boolean) => {
      context.globalCompositeOperation = "lighter";
      for (const st of stars) {
        const x = ((st.x + t * st.driftX) % width + width) % width;
        const y = ((st.y + t * st.driftY) % height + height) % height;
        let px = x, py = y, stir = 0;
        if (refract) {
          const { gx, gy } = ambientGradient(x / SCALE, y / SCALE, t);
          stir = (Math.abs(gx) + Math.abs(gy)) * REFRACT;
          px = x + gx * REFRACT;
          py = y + gy * REFRACT;
        }
        const alpha = clamp(0, 1, st.alpha * (.55 + .45 * Math.sin(st.phase + t * st.speed)) + stir * .03);
        const [r, g, b] = STAR_COLORS[st.color];
        context.globalAlpha = alpha;
        if (st.glow) {
          const size = st.size * 7;
          context.drawImage(starSprites[st.color], px - size / 2, py - size / 2, size, size);
        }
        context.fillStyle = `rgb(${r},${g},${b})`;
        context.fillRect(px, py, st.size, st.size);
        if (st.flare) {
          context.globalAlpha = alpha * .48;
          context.fillRect(px - st.size * 4.8, py - .35, st.size * 9.6, .7);
          context.fillRect(px - .35, py - st.size * 3.6, .7, st.size * 7.2);
        }
      }
      context.globalAlpha = 1;
      context.globalCompositeOperation = "source-over";
    };

    const draw = (timestamp: number) => {
      if (!start) start = timestamp;
      const t = timestamp - start;
      renderSheen(t);
      if (bg && sheen) {
        context.drawImage(bg, 0, 0, bg.width, bg.height, 0, 0, width, height);
        context.drawImage(sheen, 0, 0, bw, bh, 0, 0, width, height);
      }
      drawStars(t, true);
      frame = window.requestAnimationFrame(draw);
    };

    resize();
    if (reduced) {
      // 无障碍:静态画面一帧,不启动动画(包进闭包,与 draw 同样按声明类型读取)
      const drawStatic = () => {
        if (bg) context.drawImage(bg, 0, 0, bg.width, bg.height, 0, 0, width, height);
        drawStars(0, false);
      };
      drawStatic();
      return;
    }
    window.addEventListener("resize", resize);
    frame = window.requestAnimationFrame(draw);
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
    };
  }, [theme]);

  if (theme !== "dark") return null;

  return (
    <div className="login-starfield" aria-hidden="true">
      <canvas ref={canvasRef} />
    </div>
  );
}
