const rows = document.querySelector("#scan-rows");

function cell(value) {
  const td = document.createElement("td");
  td.textContent = value ?? "—";
  return td;
}

async function loadHistory() {
  if (!rows) return;
  const response = await fetch("/api/scans");
  if (!response.ok) throw new Error("Could not load scan history.");
  const scans = await response.json();
  rows.replaceChildren();
  if (!scans.length) {
    const row = document.createElement("tr");
    const td = cell("No scans have been recorded.");
    td.colSpan = 5;
    row.append(td);
    rows.append(row);
  }
  for (const scan of scans) {
    const row = document.createElement("tr");
    row.append(cell(scan.target_url), cell(scan.status), cell(scan.finding_count), cell(scan.started_at), cell(""));
    const link = document.createElement("a");
    link.href = `/scans/${scan.id}`;
    link.textContent = "Open report";
    row.lastElementChild.append(link);
    rows.append(row);
  }
  const select = document.querySelector("#previous-scan");
  if (select && window.SCAN_ID) {
    for (const scan of scans.filter((item) =>
      item.id < window.SCAN_ID && item.target_url === window.SCAN_TARGET)) {
      const option = document.createElement("option");
      option.value = scan.id;
      option.textContent = `#${scan.id} · ${scan.target_url}`;
      select.append(option);
    }
  }
}

document.querySelector("#compare-button")?.addEventListener("click", async () => {
  const previous = document.querySelector("#previous-scan").value;
  const output = document.querySelector("#comparison");
  if (!previous) {
    output.textContent = "Choose an earlier scan first.";
    output.classList.remove("hidden");
    return;
  }
  const response = await fetch(`/api/scans/${window.SCAN_ID}/compare/${previous}`);
  if (!response.ok) {
    output.textContent = "Could not compare scans.";
    output.classList.remove("hidden");
    return;
  }
  const result = await response.json();
  output.replaceChildren();
  for (const [label, items] of Object.entries(result)) {
    const section = document.createElement("p");
    section.textContent = `${label}: ${items.length}`;
    output.append(section);
  }
  output.classList.remove("hidden");
});

loadHistory().catch((error) => {
  if (rows) {
    rows.replaceChildren();
    const row = document.createElement("tr");
    const td = cell(error.message);
    td.colSpan = 5;
    row.append(td);
    rows.append(row);
  }
});
