/**
 * blocked.js — Extracted from blocked.html inline <script>
 */

function showDetails(index) {
  var details = document.getElementById("details" + index);
  if (details.style.display === "none" || details.style.display === "") {
    details.style.display = "table-row";
  } else {
    details.style.display = "none";
  }
}

function filterSeverity(severity) {
  const rows = document.querySelectorAll(
    '.data-table tbody tr:not([id^="details"])'
  );
  rows.forEach((row) => {
    if (severity === "all" || row.classList.contains("row-" + severity)) {
      row.style.display = "";
    } else {
      row.style.display = "none";
    }
  });

  // Hide all details rows when filtering
  const detailRows = document.querySelectorAll(
    '.data-table tbody tr[id^="details"]'
  );
  detailRows.forEach((row) => (row.style.display = "none"));
}