// 대시보드 차트 (Chart.js)
document.addEventListener('DOMContentLoaded', () => {
  const data = JSON.parse(document.getElementById('chart-data').textContent);

  Chart.defaults.color = '#7a8696';
  Chart.defaults.borderColor = '#1c232b';
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.font.size = 11;

  // 툴팁도 패널과 같은 톤으로
  const tooltip = {
    backgroundColor: '#0f1318',
    borderColor: '#2e3843',
    borderWidth: 1,
    titleColor: '#e6edf3',
    bodyColor: '#c8d0da',
    cornerRadius: 2,
    displayColors: false,
  };

  // 채도 낮춘 색 (앞쪽 색이 많이 쓰이므로 구분 잘 되는 순서로)
  const typeColors = ['#4d9de0', '#c4a13a', '#3fa66b', '#d0782f', '#8a7cc4', '#d04444', '#5fb3b3', '#7a8696'];

  new Chart(document.getElementById('typeChart'), {
    type: 'doughnut',
    data: {
      labels: data.types.labels,
      datasets: [{
        data: data.types.data,
        backgroundColor: data.types.labels.map((_, i) => typeColors[i % typeColors.length]),
        borderColor: '#12161c',
        borderWidth: 2,
      }],
    },
    options: {
      maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 8, boxHeight: 8, padding: 10 } },
        tooltip: {
          ...tooltip,
          callbacks: {
            label(ctx) {
              const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
              const pct = total ? Math.round((ctx.parsed / total) * 100) : 0;
              return `${ctx.label}: ${ctx.parsed}건 (${pct}%)`;
            },
          },
        },
      },
    },
  });

  new Chart(document.getElementById('dailyChart'), {
    type: 'line',
    data: {
      labels: data.daily.labels,
      datasets: [{
        label: '이벤트',
        data: data.daily.data,
        borderColor: '#4d9de0',
        borderWidth: 1.5,
        backgroundColor: 'rgba(77, 157, 224, 0.08)',
        fill: true,
        tension: 0,
        pointRadius: 2.5,
        pointHoverRadius: 4,
        pointBackgroundColor: '#4d9de0',
      }],
    },
    options: {
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: { ...tooltip, callbacks: { label: (ctx) => `${ctx.parsed.y}건` } },
      },
      scales: {
        y: { beginAtZero: true, ticks: { precision: 0 } },
        x: { grid: { display: false } },
      },
    },
  });
});

// 상단 시계 (관제실 시계처럼 YYYY-MM-DD HH:mm:ss)
(function clock() {
  const el = document.getElementById('clock');
  if (!el) return;
  const pad = (n) => String(n).padStart(2, '0');
  const tick = () => {
    const d = new Date();
    el.textContent = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} `
      + `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };
  tick();
  setInterval(tick, 1000);
})();
