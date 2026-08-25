const canvas = document.querySelector('#security-canvas');
const context = canvas.getContext('2d');
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
let nodes = [];

function resize() {
    canvas.width = window.innerWidth * devicePixelRatio;
    canvas.height = window.innerHeight * devicePixelRatio;
    canvas.style.width = `${window.innerWidth}px`;
    canvas.style.height = `${window.innerHeight}px`;
    context.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
    nodes = Array.from({ length: Math.min(70, Math.max(28, Math.floor(window.innerWidth / 22))) }, () => ({
        x: Math.random() * window.innerWidth,
        y: Math.random() * window.innerHeight,
        vx: (Math.random() - .5) * .22,
        vy: (Math.random() - .5) * .22,
        pulse: Math.random() * Math.PI * 2
    }));
}

function draw(time = 0) {
    context.clearRect(0, 0, window.innerWidth, window.innerHeight);
    nodes.forEach(node => {
        if (!reducedMotion) { node.x += node.vx; node.y += node.vy; node.pulse += .018; }
        if (node.x < -20 || node.x > window.innerWidth + 20) node.vx *= -1;
        if (node.y < -20 || node.y > window.innerHeight + 20) node.vy *= -1;
        nodes.forEach(other => {
            const distance = Math.hypot(node.x - other.x, node.y - other.y);
            if (distance < 145) {
                context.strokeStyle = `rgba(109, 224, 184, ${.11 * (1 - distance / 145)})`;
                context.lineWidth = 1;
                context.beginPath(); context.moveTo(node.x, node.y); context.lineTo(other.x, other.y); context.stroke();
            }
        });
        const glow = 2 + Math.sin(node.pulse + time / 1800) * 1.2;
        context.fillStyle = 'rgba(139, 246, 205, .8)';
        context.shadowColor = '#5de4b3'; context.shadowBlur = 12;
        context.beginPath(); context.arc(node.x, node.y, glow, 0, Math.PI * 2); context.fill();
        context.shadowBlur = 0;
    });
    if (!reducedMotion) requestAnimationFrame(draw);
}

resize(); draw();
window.addEventListener('resize', resize);
