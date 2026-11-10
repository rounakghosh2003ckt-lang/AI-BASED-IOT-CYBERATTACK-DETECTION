/**
 * AI-BASED IoT CYBERATTACK DETECTION SYSTEM - CORE CLIENT JS
 */

document.addEventListener("DOMContentLoaded", function () {
    // 1. Sidebar Toggle on Mobile
    const sidebarToggle = document.getElementById("sidebarToggle");
    const sidebar = document.getElementById("cyberSidebar");
    const sidebarBackdrop = document.getElementById("sidebarBackdrop");

    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener("click", function () {
            sidebar.classList.toggle("show");
            if (sidebarBackdrop) sidebarBackdrop.classList.toggle("show");
        });
    }

    if (sidebarBackdrop) {
        sidebarBackdrop.addEventListener("click", function () {
            sidebar.classList.remove("show");
            sidebarBackdrop.classList.remove("show");
        });
    }

    // 2. Real-time Clock in Navbar
    const clockEl = document.getElementById("liveClock");
    if (clockEl) {
        function updateClock() {
            const now = new Date();
            const timeStr = now.toLocaleTimeString("en-GB", { hour12: false });
            const dateStr = now.toISOString().split("T")[0];
            clockEl.textContent = `${dateStr} ${timeStr} UTC`;
        }
        updateClock();
        setInterval(updateClock, 1000);
    }

    // 3. Highlight Active Nav Item
    const currentPath = window.location.pathname;
    const navItems = document.querySelectorAll(".nav-cyber-item");
    navItems.forEach(item => {
        const href = item.getAttribute("href");
        if (href === currentPath || (currentPath === "/" && href === "/")) {
            item.classList.add("active");
        } else if (href !== "/" && currentPath.startsWith(href)) {
            item.classList.add("active");
        }
    });
});

/**
 * Global Cyber Toast Notification System
 */
function showCyberToast(title, message, type = "info") {
    let container = document.getElementById("cyberToastContainer");
    if (!container) {
        container = document.createElement("div");
        container.id = "cyberToastContainer";
        container.style.position = "fixed";
        container.style.top = "20px";
        container.style.right = "20px";
        container.style.zIndex = "9999";
        container.style.display = "flex";
        container.style.flexDirection = "column";
        container.style.gap = "10px";
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `cyber-toast toast-${type}`;
    toast.style.background = "#0f172a";
    toast.style.border = `1px solid ${type === "error" ? "#ef4444" : type === "success" ? "#00ff88" : "#00f0ff"}`;
    toast.style.borderLeft = `4px solid ${type === "error" ? "#ef4444" : type === "success" ? "#00ff88" : "#00f0ff"}`;
    toast.style.color = "#f8fafc";
    toast.style.padding = "12px 18px";
    toast.style.borderRadius = "6px";
    toast.style.minWidth = "280px";
    toast.style.boxShadow = "0 10px 25px rgba(0,0,0,0.5)";
    toast.style.fontFamily = "'Inter', sans-serif";
    toast.style.fontSize = "0.88rem";
    toast.style.animation = "fadeIn 0.3s ease";

    toast.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
            <strong style="color:${type === "error" ? "#ef4444" : type === "success" ? "#00ff88" : "#00f0ff"}; font-family:'Rajdhani',sans-serif; font-size:1rem; text-transform:uppercase;">${title}</strong>
            <span style="cursor:pointer; opacity:0.6; font-size:1.1rem;" onclick="this.parentElement.parentElement.remove()">&times;</span>
        </div>
        <div style="color:#94a3b8; font-size:0.82rem;">${message}</div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transition = "opacity 0.4s ease";
        setTimeout(() => toast.remove(), 400);
    }, 4500);
}
