/**
 * CyberShield Pro - Dobby AI Security Assistant
 */

const Chatbot = {
  isOpen: false,
  incidentId: null,

  init() {
    // Load state from session storage
    const savedState = sessionStorage.getItem("dobbydata");
    if (savedState) {
      const state = JSON.parse(savedState);
      this.isOpen = state.isOpen;
      // Don't restore incidentId from session, as it depends on current page
    }

    // Check if we are on a specific incident page
    if (typeof incidentId !== "undefined") {
      this.incidentId = incidentId;
    }

    // HTML should be present in the DOM via chatbot.html include
    if (!document.getElementById("chatbot-window")) {
      console.warn("Dobby: Chatbot window elements not found in DOM.");
      return;
    }

    this.restoreHistory();
    this.bindEvents();

    // Auto-open if it was open before
    if (this.isOpen) {
      document.getElementById("chatbot-window").classList.add("active");
      document.getElementById("chatbot-fab").style.display = "none";
    }

    // Dobby Greeting if history is empty
    if (!sessionStorage.getItem("dobbyhistory")) {
      this.sendGreeting();
    }
  },

  saveState() {
    sessionStorage.setItem(
      "dobbydata",
      JSON.stringify({
        isOpen: this.isOpen,
      }),
    );
  },

  saveHistory(role, content) {
    let history = JSON.parse(sessionStorage.getItem("dobbyhistory") || "[]");
    history.push({ role, content });
    if (history.length > 20) history.shift(); // Keep last 20 messages
    sessionStorage.setItem("dobbyhistory", JSON.stringify(history));
  },

  restoreHistory() {
    const history = JSON.parse(sessionStorage.getItem("dobbyhistory") || "[]");
    const container = document.getElementById("chat-messages");
    if (!container) return;
    container.innerHTML = ""; // Clear initial static message

    history.forEach((msg) => {
      this.appendMessageToDOM(msg.content, msg.role);
    });
  },

  bindEvents() {
    const fab = document.getElementById("chatbot-fab");
    const close = document.getElementById("close-chat");
    const send = document.getElementById("send-btn");
    const input = document.getElementById("chat-input");

    fab.addEventListener("click", () => this.toggleChat());
    close.addEventListener("click", () => this.toggleChat());

    send.addEventListener("click", () => this.sendMessage());

    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        this.sendMessage();
      }
    });
  },

  toggleChat() {
    this.isOpen = !this.isOpen;
    this.saveState();

    const window = document.getElementById("chatbot-window");
    const fab = document.getElementById("chatbot-fab");

    if (this.isOpen) {
      window.classList.add("active");
      fab.style.display = "none";
      document.getElementById("chat-input").focus();

      // Scroll to bottom
      const container = document.getElementById("chat-messages");
      container.scrollTop = container.scrollHeight;
    } else {
      window.classList.remove("active");
      fab.style.display = "flex";
    }
  },

  appendMessageToDOM(text, sender) {
    const container = document.getElementById("chat-messages");
    const msgDiv = document.createElement("div");
    msgDiv.className = `message ${sender}`;
    msgDiv.innerHTML = this.formatText(text);
    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
  },

  appendMessage(text, sender) {
    this.appendMessageToDOM(text, sender);
    this.saveHistory(sender, text);
  },

  showTyping() {
    const container = document.getElementById("chat-messages");
    const indicator = document.createElement("div");
    indicator.className = "typing-indicator";
    indicator.id = "typing-indicator";
    indicator.innerHTML = `
            <div class="typing-dot"></div>
            <div class="typing-dot"></div>
            <div class="typing-dot"></div>
        `;
    container.appendChild(indicator);
    container.scrollTop = container.scrollHeight;
  },

  hideTyping() {
    const indicator = document.getElementById("typing-indicator");
    if (indicator) indicator.remove();
  },

  getContext() {
    return {
      path: window.location.pathname,
      query: Object.fromEntries(new URLSearchParams(window.location.search)),
    };
  },

  async sendGreeting() {
    // Dobby introduces himself contextually if it's a new session
    const context = this.getContext();
    let greeting = "Hello! I am Dobby, your Security Assistant. ";

    if (context.path.includes("incidents")) {
      if (context.query.category) {
        greeting += `I see you are filtering for <strong>${context.query.category}</strong> incidents.`;
      } else {
        greeting += "I can help you analyze these incidents.";
      }
    } else if (context.path.includes("threats")) {
      const type = context.path
        .split("/")
        .pop()
        .replace("-", " ")
        .toUpperCase();
      greeting += `I am monitoring <strong>${type}</strong> activities. Need an analysis?`;
    } else if (context.path.includes("ml-detections")) {
      greeting +=
        "I am investigating <strong>AI-detected anomalies</strong> in the system.";
    } else if (context.path.includes("blocked")) {
      greeting +=
        "I am observing the <strong>Blocked IP list</strong> and firewall events.";
    } else if (this.incidentId) {
      greeting += `I am ready to analyze incident <code>${this.incidentId}</code>.`;
    } else {
      greeting += "I am monitoring the system health.";
    }

    this.appendMessage(greeting, "bot");
  },

  async sendMessage() {
    const input = document.getElementById("chat-input");
    const text = input.value.trim();
    if (!text) return;

    // UI Updates
    this.appendMessage(text, "user");
    input.value = "";
    this.showTyping();

    try {
      const payload = {
        message: text,
        incident_id: this.incidentId,
        page_context: this.getContext(),
        history: JSON.parse(sessionStorage.getItem("dobbyhistory") || "[]"),
      };

      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (response.status === 401) {
        this.hideTyping();
        this.appendMessage("⚠️ my session expired. Please login again.", "bot");
        return;
      }

      const data = await response.json();

      this.hideTyping();

      if (data.error) {
        this.appendMessage(`⚠️ Error: ${data.error}`, "bot");
      } else {
        this.appendMessage(data.response, "bot");
      }
    } catch (error) {
      this.hideTyping();
      this.appendMessage("⚠️ I cannot reach the server right now.", "bot");
      console.error(error);
    }
  },

  formatText(text) {
    return text
      .replace(/\n/g, "<br>")
      .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
      .replace(/`(.*?)`/g, "<code>$1</code>")
      .replace(/- (.*?)(<br>|$)/g, "<li>$1</li>");
  },
};

document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => Chatbot.init(), 500);
});


