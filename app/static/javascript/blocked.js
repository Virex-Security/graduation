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
document.addEventListener("DOMContentLoaded", function () {
        // Sidebar functionality is now handled by layout.js

        const sidebarResetBtn = document.getElementById("sidebar-reset-btn");
        if (sidebarResetBtn) {
          sidebarResetBtn.addEventListener("click", function () {
            if (
              confirm(
                "هل أنت متأكد من إعادة تعيين جميع الإحصائيات؟ لا يمكن التراجع عن هذا الإجراء."
              )
            ) {
              fetch("/api/dashboard/reset", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                  "Content-Type": "application/json",
                },
              })
                .then((response) => response.json())
                .then((data) => {
                  if (data.status === "stats_reset") {
                    alert("تم إعادة تعيين الإحصائيات بنجاح!");
                    location.reload();
                  }
                })
                .catch((error) => {
                  console.error("Reset error:", error);
                  alert("فشل في إعادة تعيين الإحصائيات");
                });
            }
          });
        }
      });
      function normalize(s) {
  return (s || "").toString().trim().toLowerCase();
}

function applyFilters() {
  const sev = document.getElementById("filter-severity")?.value || "all";
  const typ = document.getElementById("filter-attack-type")?.value || "all";
  const ipq = document.getElementById("filter-ip")?.value || "";

  const sevN = normalize(sev);
  const typN = normalize(typ);
  const ipN  = normalize(ipq);

  const rows = document.querySelectorAll("tr.event-row");

  rows.forEach((row) => {
    const rowSev = normalize(row.getAttribute("data-severity"));
    const rowTyp = normalize(row.getAttribute("data-attack-type"));
    const rowIp  = normalize(row.getAttribute("data-ip"));

    const matchSeverity = (sevN === "all") || (rowSev === sevN);
    const matchType     = (typN === "all") || (rowTyp === typN);
    const matchIP       = (!ipN) || rowIp.includes(ipN);

    row.style.display = (matchSeverity && matchType && matchIP) ? "" : "none";
  });
}

function resetFilters() {
  const s = document.getElementById("filter-severity");
  const t = document.getElementById("filter-attack-type");
  const i = document.getElementById("filter-ip");
  if (s) s.value = "all";
  if (t) t.value = "all";
  if (i) i.value = "";
  applyFilters();
}

document.addEventListener("DOMContentLoaded", () => {
  const s = document.getElementById("filter-severity");
  const t = document.getElementById("filter-attack-type");
  const i = document.getElementById("filter-ip");
  const a = document.getElementById("filter-apply");
  const r = document.getElementById("filter-reset");
  const ip = document.getElementById("filter-ip");

  if (a) a.addEventListener("click", applyFilters);
  if (r) r.addEventListener("click", resetFilters);
  if (ip) {
    ip.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        applyFilters();
      }
    });
  }
});

