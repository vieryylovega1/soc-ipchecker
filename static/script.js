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

  const excludeKeyword = document.getElementById("excludeEventKeyword").value.trim().toLowerCase();
  const excludeScoreInput = document.getElementById("excludeAbuseScore").value.trim();
  const excludeScore = excludeScoreInput ? parseInt(excludeScoreInput) : null;

  const res = await fetch("/analyze", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({report_text: reportText})
  });

  const data = await res.json();

  let filteredResults = data.results;

    // Filter exclude multiple keywords (pisahkan dengan koma)
    if (excludeKeyword) {
    const keywords = excludeKeyword
        .split(",")
        .map(k => k.trim().toLowerCase())
        .filter(k => k.length > 0);

    filteredResults = filteredResults.filter(row => {
        const eventName = (row.eventName || "").toLowerCase();

        // jika eventName mengandung salah satu keyword, maka exclude
        for (let k of keywords) {
        if (eventName.includes(k)) {
            return false;
        }
        }
        return true;
    });
    }

  // Filter exclude abuse score >= X
  if (excludeScore !== null && !isNaN(excludeScore)) {
    filteredResults = filteredResults.filter(row => {
      const score = row.abuseScore;
      if (score === null || score === undefined) return true;
      return score < excludeScore;
    });
  }

  document.getElementById("summary").innerText =
    `Total Events: ${data.total_events} | Unique Source IP: ${data.total_unique_ips} | Displayed: ${filteredResults.length}`;

  // Sorting
  filteredResults.sort((a, b) => {
    let valA, valB;

    if (sortField === "count") {
      valA = getSafeNumber(a.count);
      valB = getSafeNumber(b.count);
    } else if (sortField === "abuseScore") {
      valA = getSafeNumber(a.abuseScore);
      valB = getSafeNumber(b.abuseScore);
    } else if (sortField === "eventName") {
      valA = getSafeText(a.eventName);
      valB = getSafeText(b.eventName);
    }

    if (sortDirection === "asc") {
      if (valA > valB) return 1;
      if (valA < valB) return -1;
      return 0;
    } else {
      if (valA > valB) return -1;
      if (valA < valB) return 1;
      return 0;
    }
  });

  // Render table
  const tbody = document.querySelector("#resultTable tbody");
  tbody.innerHTML = "";

  filteredResults.forEach(row => {
    const tr = document.createElement("tr");

    tr.innerHTML = `
      <td>${row.eventName || ""}</td>
      <td>${row.sourceIP || ""}</td>
      <td>${row.url || ""}</td>
      <td>${row.action || ""}</td>
      <td>${row.count || ""}</td>
      <td>${row.abuseScore ?? ""}</td>
      <td>${row.totalReports ?? ""}</td>
      <td>${row.isp || ""}</td>
      <td>${row.countryCode || ""}</td>
      <td>${row.domain || ""}</td>
    `;

    tbody.appendChild(tr);
  });
}

async function downloadCSV() {
  const reportText = document.getElementById("report").value;

  const res = await fetch("/download_csv", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({report_text: reportText})
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

  const confirmClear = confirm("Apakah kamu yakin ingin menghapus seluruh cache?");
  if (!confirmClear) return;

  const res = await fetch(`/clear_cache?token=${encodeURIComponent(token)}`, {
    method: "POST"
  });

  const data = await res.json();

  if (data.status === "SUCCESS") {
    alert("Cache berhasil dihapus!");
  } else {
    alert("Gagal clear cache! Token salah atau unauthorized.");
  }
}