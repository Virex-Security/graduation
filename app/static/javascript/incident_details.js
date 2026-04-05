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
    const incidentId = document.getElementById("incident-id")?.value;

    async function performAction(action) {
      const comment = document.getElementById("action-comment").value;

      const response = await fetch(`/api/incident/${incidentId}/action`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, comment }),
      });

      const result = await response.json();
      if (result.status === "success") {
        document.getElementById("action-comment").value = "";
        location.reload();
      } else {
        alert("Error: " + result.message);
      }
    }

    async function exportIncident() {
  window.open(`/api/incident/${incidentId}/export`, "_blank");
}

    window.onload = () => {
      console.log("Incident details loaded from server-side template");
    };


