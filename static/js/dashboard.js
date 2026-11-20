const form = document.querySelector("#scan-form");
const message = document.querySelector("#form-message");
let activeScan = null;
let pollTimer = null;

function makeCell(value) {
  const cell = document.createElement("td");
  cell.textContent = value ?? "—";
  return cell;
}

function renderScans(scans) {
  const body = document.querySelector("#scan-rows");
  body.replaceChildren();
  if (!scans.length) {
    const row = document.createElement("tr");
    const cell = makeCell("No scans yet. Start a local scan to populate this table.");
    cell.colSpan = 5;
    row.append(cell);
    body.append(row);
  }
  for (const scan of scans.slice(0, 8)) {
    const row = document.createElement("tr");
    row.append(makeCell(scan.target_url), makeCell(scan.status), makeCell(scan.finding_count),
      makeCell(scan.started_at), makeCell(""));
    const link = document.createElement("a");
    link.href = `/scans/${scan.id}`;
    link.textContent = "Open report";
    row.lastElementChild.append(link);
    body.append(row);
  }
  document.querySelector("#total-scans").textContent = scans.length;
  document.querySelector("#total-findings").textContent =
    scans.reduce((total, scan) => total + Number(scan.finding_count || 0), 0);
  document.querySelector("#latest-scan").textContent = scans[0]
    ? new Date(scans[0].started_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : "—";
}

async function loadScans() {
  const response = await fetch("/api/scans");
  if (!response.ok) throw new Error("Could not load scan history.");
  renderScans(await response.json());
}

function updateProgress(scan) {
  document.querySelector("#progress-empty").classList.add("hidden");
  document.querySelector("#progress-view").classList.remove("hidden");
  document.querySelector("#progress-target").textContent = scan.target_url;
  document.querySelector("#progress-percent").textContent = `${scan.progress}%`;
  document.querySelector("#progress-bar").style.width = `${scan.progress}%`;
  document.querySelector("#progress-step").textContent = scan.current_step;
  const result = document.querySelector("#progress-result");
  if (["completed", "completed_with_errors", "failed"].includes(scan.status)) {
    result.href = `/scans/${scan.id}`;
    result.classList.remove("hidden");
    clearInterval(pollTimer);
    pollTimer = null;
    loadScans().catch((error) => {
      message.textContent = error.message;
    });
  }
}

async function pollScan() {
  if (!activeScan) return;
  try {
    const response = await fetch(`/api/scans/${activeScan}`);
    if (!response.ok) throw new Error("Unable to retrieve scan progress.");
    updateProgress(await response.json());
  } catch (error) {
    clearInterval(pollTimer);
    pollTimer = null;
    message.textContent = error.message;
  }
}

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  message.textContent = "Starting local scan…";
  const response = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target_url: document.querySelector("#target-url").value,
      authorized: document.querySelector("#authorized").checked,
    }),
  });
  const result = await response.json();
  if (!response.ok) {
    message.textContent = result.error || "Could not start the scan.";
    return;
  }
  activeScan = result.id;
  message.textContent = `Scan #${activeScan} started.`;
  document.querySelector("#progress-result").classList.add("hidden");
  await pollScan();
  pollTimer = setInterval(pollScan, 1000);
});

loadScans().catch((error) => {
  message.textContent = error.message;
});
