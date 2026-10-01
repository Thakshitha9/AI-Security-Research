const MODULE_CHECKS = [
    {
        id: "statusPhishing",
        url: "http://127.0.0.1:5000/api/health"
    },
    {
        id: "statusRag",
        url: "http://127.0.0.1:5000/api/health"
    },
    {
        id: "statusPrompt",
        url: "http://127.0.0.1:5001/api/prompt-guard/health"
    },
    {
        id: "statusRecon",
        url: "http://127.0.0.1:5002/api/recon/health"
    },
    {
        id: "statusReports",
        url: "http://127.0.0.1:5003/api/security-report/health"
    }
];

function setText(id, value) {
    const element = document.getElementById(id);

    if (element) {
        element.textContent = value;
    }
}

function riskLabel(score, supplied) {
    if (supplied) {
        return String(supplied).toUpperCase();
    }

    const value = Number(score);

    if (Number.isNaN(value)) {
        return "UNKNOWN";
    }

    if (value >= 70) {
        return "HIGH";
    }

    if (value >= 40) {
        return "MEDIUM";
    }

    if (value > 0) {
        return "LOW";
    }

    return "INFO";
}

function showNotice(message, isError) {
    const notice = document.getElementById("dashboardNotice");

    if (!notice) {
        return;
    }

    if (!message) {
        notice.hidden = true;
        notice.textContent = "";
        return;
    }

    notice.hidden = false;
    notice.textContent = message;
    notice.className = isError
        ? "dashboard-notice error"
        : "dashboard-notice";
}

function renderLatest(item) {
    const container = document.getElementById("latestFinding");

    if (!container) {
        return;
    }

    container.replaceChildren();

    if (!item) {
        const empty = document.createElement("p");
        empty.className = "empty-copy";
        empty.textContent =
            "No stored findings yet. Run an analysis to see the " +
            "risk level, evidence, and recommendation here.";
        container.appendChild(empty);
        return;
    }

    const level = riskLabel(item.risk_score, item.risk_level);
    const rows = [
        ["Risk Level", level],
        ["Module", item.module || "Analysis"],
        ["Target", item.target || item.url || "Not stored"],
        ["Finding", item.finding || "No finding text was stored for this record."],
        [
            "Recommendation",
            item.recommendation || "No recommendation was stored for this record."
        ]
    ];

    const list = document.createElement("dl");
    list.className = "assessment-list";

    rows.forEach(function (row) {
        const term = document.createElement("dt");
        term.textContent = row[0];

        const detail = document.createElement("dd");
        detail.textContent = row[1];

        list.appendChild(term);
        list.appendChild(detail);
    });

    container.appendChild(list);
}

function renderActivity(items) {
    const activityList = document.getElementById("activityList");

    if (!activityList) {
        return;
    }

    activityList.replaceChildren();

    if (!items || items.length === 0) {
        const empty = document.createElement("div");
        empty.className = "activity-item";

        const info = document.createElement("div");
        info.className = "activity-info";

        const title = document.createElement("strong");
        title.textContent = "No security activity yet";

        const detail = document.createElement("span");
        detail.textContent = "Stored analyses will appear here.";

        info.appendChild(title);
        info.appendChild(detail);
        empty.appendChild(info);
        activityList.appendChild(empty);
        return;
    }

    items.forEach(function (item) {
        const level = riskLabel(item.risk_score, item.risk_level);
        const riskClass = level === "HIGH"
            ? "high"
            : (level === "MEDIUM" ? "medium" : "low");

        const row = document.createElement("div");
        row.className = "activity-item";

        const icon = document.createElement("div");
        icon.className = "activity-icon " + riskClass;
        icon.textContent = level === "HIGH" ? "!" : "•";

        const info = document.createElement("div");
        info.className = "activity-info";

        const title = document.createElement("strong");
        title.textContent = item.module || "Security analysis";

        const target = document.createElement("span");
        target.textContent = item.target || item.url || "Target not stored";

        info.appendChild(title);
        info.appendChild(target);

        if (item.finding) {
            const finding = document.createElement("span");
            finding.textContent = "Finding: " + item.finding;
            info.appendChild(finding);
        }

        const badge = document.createElement("span");
        badge.className = "badge " + riskClass;
        badge.textContent = level;

        const time = document.createElement("time");
        time.textContent = item.created_at
            ? new Date(item.created_at).toLocaleString()
            : "Time not recorded";

        row.appendChild(icon);
        row.appendChild(info);
        row.appendChild(badge);
        row.appendChild(time);
        activityList.appendChild(row);
    });
}

async function checkModule(check) {
    const element = document.getElementById(check.id);

    if (!element) {
        return false;
    }

    try {
        const response = await fetch(check.url, {
            signal: AbortSignal.timeout(2000)
        });

        if (!response.ok) {
            throw new Error("offline");
        }

        element.textContent = "Online";
        element.classList.add("online");
        element.classList.remove("offline");
        return true;
    } catch (error) {
        element.textContent = "Offline";
        element.classList.add("offline");
        element.classList.remove("online");
        return false;
    }
}

async function loadModuleStatus() {
    const results = await Promise.all(
        MODULE_CHECKS.map(checkModule)
    );
    const online = results.filter(Boolean).length;
    const engine = document.getElementById("engineStatus");
    const sidebar = document.getElementById("sidebarStatus");

    if (engine) {
        engine.textContent = online
            ? online + " of " + results.length + " APIs online"
            : "No local APIs responded";
    }

    if (sidebar) {
        sidebar.textContent = online
            ? online + " local APIs responded"
            : "Start an API to analyze";
    }
}

async function loadDashboardStats() {
    try {
        const response = await fetch(
            "http://127.0.0.1:5000/api/dashboard/stats"
        );

        if (!response.ok) {
            throw new Error("Unable to load dashboard statistics");
        }

        const data = await response.json();
        const hasHistory = Number(data.total) > 0;

        setText("phishingDetected", hasHistory ? data.high_risk : "—");
        setText("securityScans", hasHistory ? data.total : "—");
        setText("mediumRisk", hasHistory ? data.medium_risk : "—");
        setText("lowRisk", hasHistory ? data.low_risk : "—");
        setText(
            "averageRiskScore",
            data.average_risk === null || data.average_risk === undefined
                ? "—"
                : data.average_risk
        );

        if (data.database !== "online") {
            showNotice(
                data.message || "Analysis history is unavailable.",
                true
            );
        } else if (!hasHistory) {
            showNotice(data.message || "No analyses have been stored yet.", false);
        } else {
            showNotice("", false);
        }

        const recent = Array.isArray(data.recent_analyses)
            ? data.recent_analyses
            : [];

        renderActivity(recent);
        renderLatest(recent[0]);
    } catch (error) {
        showNotice(
            "Dashboard API is unavailable. Start the main API on port 5000. Counts stay blank until history can be read.",
            true
        );
        const activityList = document.getElementById("activityList");

        if (activityList) {
            activityList.replaceChildren();
            const row = document.createElement("div");
            row.className = "activity-item";
            const info = document.createElement("div");
            info.className = "activity-info";
            const title = document.createElement("strong");
            title.textContent = "Dashboard API unavailable";
            const detail = document.createElement("span");
            detail.textContent = "Start the main API on port 5000.";
            info.appendChild(title);
            info.appendChild(detail);
            row.appendChild(info);
            activityList.appendChild(row);
        }

        const latest = document.getElementById("latestFinding");

        if (latest) {
            latest.replaceChildren();
            const empty = document.createElement("p");
            empty.className = "empty-copy";
            empty.textContent =
                "The latest finding cannot be loaded until the dashboard API responds.";
            latest.appendChild(empty);
        }

        setText("phishingDetected", "—");
        setText("securityScans", "—");
        setText("mediumRisk", "—");
        setText("lowRisk", "—");
        setText("averageRiskScore", "—");
    }
}

loadDashboardStats();
loadModuleStatus();
