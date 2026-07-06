/* ==========================================================================
   CYBERDEFENSE PRO - INTERACTIVE LOGIC
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
    initParticles();
    initStatsCounter();
    initCardFlip();
});





// Background Animation — Binary Rain (1s and 0s)
function initParticles() {
    const canvasContainer = document.getElementById("bgParticles");
    if (!canvasContainer) return;

    const canvas = document.createElement("canvas");
    canvasContainer.appendChild(canvas);
    const ctx = canvas.getContext("2d");

    let width  = (canvas.width  = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const FONT_SIZE = 14;
    let drops = [];

    function initDrops() {
        drops = [];
        const cols = Math.floor(width / FONT_SIZE);
        for (let i = 0; i < cols; i++) {
            drops.push({
                y:       Math.random() * -height,         // start above screen
                speed:   0.4 + Math.random() * 1.0,       // different fall speeds
                opacity: 0.04 + Math.random() * 0.07,     // subtle opacity
                length:  12 + Math.floor(Math.random() * 20), // trail length
                bits:    [],                               // 0/1 chars
            });
            for (let j = 0; j < drops[i].length; j++) {
                drops[i].bits.push(Math.random() > 0.5 ? "1" : "0");
            }
        }
    }
    initDrops();

    window.addEventListener("resize", () => {
        width  = (canvas.width  = window.innerWidth);
        height = (canvas.height = window.innerHeight);
        initDrops();
    });

    function isLight() {
        return document.documentElement.getAttribute("data-theme") === "light";
    }

    function animate() {
        const light = isLight();

        // Fade the previous frame — creates the trailing tail effect
        ctx.fillStyle = light
            ? "rgba(240, 244, 255, 0.18)"
            : "rgba(8, 12, 24, 0.14)";
        ctx.fillRect(0, 0, width, height);

        ctx.font = `bold ${FONT_SIZE}px 'JetBrains Mono', 'Courier New', monospace`;

        drops.forEach((drop, xi) => {
            const x = xi * FONT_SIZE;

            drop.bits.forEach((bit, yi) => {
                const y = drop.y + yi * FONT_SIZE;
                if (y < 0 || y > height) return;

                // Position in trail: 0 = head (brightest), 1 = tail (faintest)
                const t    = yi / drop.length;
                const fade = (1 - t) * drop.opacity;

                // Head bit gets an extra bright highlight
                const isHead = yi === 0;
                let alpha = isHead ? Math.min(fade * 3.5, 0.55) : fade;

                if (light) {
                    // Blue-teal tones for light mode
                    const r = isHead ? 37 : 59;
                    const g = isHead ? 99 : 130;
                    const b = isHead ? 235 : 246;
                    ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${alpha})`;
                } else {
                    // Classic green for dark mode
                    const r = isHead ? 74  : 16;
                    const g = isHead ? 222 : 185;
                    const b = isHead ? 128 : 129;
                    ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${alpha})`;
                }

                ctx.fillText(bit, x, y);
            });

            // Advance drop
            drop.y += drop.speed;

            // Randomly flip bits for a flickering effect
            if (Math.random() < 0.05) {
                const idx = Math.floor(Math.random() * drop.bits.length);
                drop.bits[idx] = drop.bits[idx] === "1" ? "0" : "1";
            }

            // Reset when fully off-screen
            if (drop.y - drop.length * FONT_SIZE > height) {
                drop.y = -drop.length * FONT_SIZE * Math.random();
                drop.speed = 0.4 + Math.random() * 1.0;
                drop.opacity = 0.04 + Math.random() * 0.07;
            }
        });

        requestAnimationFrame(animate);
    }

    animate();
}

// Stats Counter animation
function initStatsCounter() {
    const counters = document.querySelectorAll(".counter");
    if (counters.length === 0) return;

    const observerOptions = {
        root: null,
        threshold: 0.1,
    };

    const observer = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const target = entry.target;
                const limit = parseInt(target.getAttribute("data-target"), 10) || 0;
                let current = 0;
                const duration = 1200; // ms
                const stepTime = Math.max(Math.floor(duration / limit), 20);

                const timer = setInterval(() => {
                    current += Math.ceil(limit / 30) || 1;
                    if (current >= limit) {
                        target.textContent = limit;
                        clearInterval(timer);
                    } else {
                        target.textContent = current;
                    }
                }, stepTime);

                observer.unobserve(target);
            }
        });
    }, observerOptions);

    counters.forEach(c => observer.observe(c));
}

// 3D Card Flip on Scroll
function initCardFlip() {
    const selectors = [
        '.threats-grid > .threat-card',
        '.awareness-cards-grid > .awareness-card',
        '.features-grid > .feature-card',
        '.guides-grid > .guide-card',
        '.stats-grid > .stat-card',
        '.first-aid-grid > .first-aid-card',
        '.info-cards-grid > .info-card',
        '.checks-results-grid > .check-result-card',
        '.net-hosts-grid > .net-host-card',
        '.steps-container > .step-card',
    ];

    const cards = document.querySelectorAll(selectors.join(','));
    if (cards.length === 0) return;

    cards.forEach(card => {
        const parent = card.parentElement;
        parent.classList.add('perspective-grid');
        card.classList.add('flip-card');
    });

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const card = entry.target;
                const siblings = Array.from(card.parentElement.children);
                const index = siblings.indexOf(card);
                card.style.transitionDelay = `${Math.min(index * 0.08, 0.8)}s`;
                card.classList.add('flipped');
                observer.unobserve(card);
            }
        });
    }, { threshold: 0.1 });

    cards.forEach(c => observer.observe(c));
}
