function toggleTheme() {
  const body = document.body;
  const button = document.getElementById("themeButton");

  body.classList.toggle("dark-mode");

  const isDark = body.classList.contains("dark-mode");
  localStorage.setItem("theme", isDark ? "dark" : "light");

  if (button) {
    button.innerHTML = isDark ? "☀️ Light Mode" : "🌙 Dark Mode";
  }
}

function loadSavedTheme() {
  const savedTheme = localStorage.getItem("theme");
  const button = document.getElementById("themeButton");

  if (savedTheme === "dark") {
    document.body.classList.add("dark-mode");
    if (button) button.innerHTML = "☀️ Light Mode";
  } else {
    document.body.classList.remove("dark-mode");
    if (button) button.innerHTML = "🌙 Dark Mode";
  }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text || "")
    .then(() => alert("Copied IP: " + text))
    .catch(() => alert("Gagal copy IP!"));
}

function getAbuseBadge(score) {
  if (score === null || score === undefined || score === "") {
    return `<span class="badge badge-na">N/A</span>`;
  }

  const num = parseInt(score);
  if (isNaN(num)) {
    return `<span class="badge badge-na">N/A</span>`;
  }

  if (num <= 20) {
    return `<span class="badge badge-low">${num}</span>`;
  }

  if (num <= 50) {
    return `<span class="badge badge-medium">${num}</span>`;
  }

  return `<span class="badge badge-high">${num}</span>`;
}

function getSafeNumber(value) {
  const num = parseInt(value);
  return isNaN(num) ? 0 : num;
}

function getSafeText(value) {
  return (value || "").toString().toLowerCase();
}

async function analyze() {
  const reportText = document.getElementById("report").value;
  const sortField = document.getElementById("sortField").value;
  const sortDirection = document.getElementById("sortDirection").value;

  const excludeKeywordInput = document
    .getElementById("excludeEventKeyword")
    .value
    .trim()
    .toLowerCase();

  const excludeScoreInput = document
    .getElementById("excludeAbuseScore")
    .value
    .trim();

  const excludeScore = excludeScoreInput ? parseInt(excludeScoreInput) : null;

  const res = await fetch("/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ report_text: reportText })
  });

  const data = await res.json();
  let filteredResults = data.results || [];

  if (excludeKeywordInput) {
    const keywords = excludeKeywordInput
      .split(",")
      .map(k => k.trim())
      .filter(Boolean);

    filteredResults = filteredResults.filter(row => {
      const eventName = getSafeText(row.eventName);
      return !keywords.some(k => eventName.includes(k));
    });
  }

  if (excludeScore !== null && !isNaN(excludeScore)) {
    filteredResults = filteredResults.filter(row => {
      const score = getSafeNumber(row.abuseScore);
      return score < excludeScore;
    });
  }

  document.getElementById("summary").innerText =
    `Total Events: ${data.total_events} | Unique Source IP: ${data.total_unique_ips} | Displayed: ${filteredResults.length}`;

  filteredResults.sort((a, b) => {
    let valA;
    let valB;

    if (sortField === "count") {
      valA = getSafeNumber(a.count);
      valB = getSafeNumber(b.count);
    } else if (sortField === "abuseScore") {
      valA = getSafeNumber(a.abuseScore);
      valB = getSafeNumber(b.abuseScore);
    } else {
      valA = getSafeText(a.eventName);
      valB = getSafeText(b.eventName);
    }

    if (valA === valB) return 0;

    return sortDirection === "asc"
      ? (valA > valB ? 1 : -1)
      : (valA < valB ? 1 : -1);
  });

  const tbody = document.querySelector("#resultTable tbody");
  tbody.innerHTML = "";

  filteredResults.forEach(row => {
    const tr = document.createElement("tr");

    tr.innerHTML = `
      <td>
        <span class="copy-ip" onclick="copyToClipboard('${row.sourceIP || ""}')">
          ${row.sourceIP || ""}
        </span>
      </td>
      <td>${row.isp || "-"}</td>
      <td>${row.countryCode || "-"}</td>
      <td>${row.city || "-"}</td>
      <td>${row.totalReports ?? "-"}</td>
      <td>${getAbuseBadge(row.abuseScore)}</td>
      <td>${row.lastReportedAt || "-"}</td>
      <td>${row.checkedAt || "-"}</td>
      <td>${row.domain || "-"}</td>
      <td>${row.eventName || "-"}</td>
      <td>${row.count || "-"}</td>
      <td>${row.action || "-"}</td>
      <td>${row.usageType || "-"}</td>
      <td>${row.asn || "-"}</td>
    `;

    tbody.appendChild(tr);
  });

  applySavedColumnWidths();
}

async function downloadCSV() {
  const reportText = document.getElementById("report").value;

  const res = await fetch("/download_csv", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ report_text: reportText })
  });

  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "soc_ip_reputation_report.csv";
  a.click();

  window.URL.revokeObjectURL(url);
}

async function clearCache() {
  const token = document.getElementById("adminToken").value;

  if (!token) {
    alert("Masukkan Admin Token terlebih dahulu!");
    return;
  }

  if (!confirm("Apakah kamu yakin ingin menghapus seluruh cache?")) return;

  const res = await fetch(`/clear_cache?token=${encodeURIComponent(token)}`, {
    method: "POST"
  });

  const data = await res.json();

  alert(
    data.status === "SUCCESS"
      ? "Cache berhasil dihapus!"
      : "Gagal clear cache! Token salah atau unauthorized."
  );
}

function setColumnWidth(columnIndex, width) {
  const table = document.getElementById("resultTable");
  const rows = table.querySelectorAll("tr");

  rows.forEach(row => {
    const cell = row.children[columnIndex];
    if (cell) {
      cell.style.width = `${width}px`;
      cell.style.minWidth = `${width}px`;
      cell.style.maxWidth = `${width}px`;
    }
  });
}

function saveColumnWidth(columnIndex, width) {
  const saved = JSON.parse(localStorage.getItem("columnWidths") || "{}");
  saved[columnIndex] = width;
  localStorage.setItem("columnWidths", JSON.stringify(saved));
}

function applySavedColumnWidths() {
  const saved = JSON.parse(localStorage.getItem("columnWidths") || "{}");

  Object.keys(saved).forEach(index => {
    setColumnWidth(parseInt(index), saved[index]);
  });
}

function initResizableColumns() {
  const headers = document.querySelectorAll("#resultTable th.resizable");

  headers.forEach((th, index) => {
    if (th.querySelector(".resizer")) return;

    const resizer = document.createElement("span");
    resizer.className = "resizer";
    th.appendChild(resizer);

    let startX = 0;
    let startWidth = 0;

    resizer.addEventListener("mousedown", (e) => {
      e.preventDefault();
      e.stopPropagation();

      startX = e.pageX;
      startWidth = th.offsetWidth;

      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";

      function resize(e) {
        const newWidth = Math.max(70, startWidth + (e.pageX - startX));
        setColumnWidth(index, newWidth);
      }

      function stopResize() {
        const finalWidth = th.offsetWidth;
        saveColumnWidth(index, finalWidth);

        document.body.style.cursor = "";
        document.body.style.userSelect = "";

        document.removeEventListener("mousemove", resize);
        document.removeEventListener("mouseup", stopResize);
      }

      document.addEventListener("mousemove", resize);
      document.addEventListener("mouseup", stopResize);
    });
  });

  applySavedColumnWidths();
}

window.addEventListener("DOMContentLoaded", () => {
  loadSavedTheme();
  initResizableColumns();
});