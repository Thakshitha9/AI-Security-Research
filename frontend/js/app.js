// ================================
// AI SECURITY PLATFORM
// Dashboard Interactions
// ================================

// Sidebar navigation
const navItems = document.querySelectorAll(".nav-item");

navItems.forEach((item) => {
    item.addEventListener("click", function (event) {
        const href = item.getAttribute("href");

        if (href && href !== "#") {
            return;
        }

        event.preventDefault();
    });
});


// View All scrolls to the stored history on this page.
const viewButton = document.querySelector(".view-button");

if (viewButton) {
    viewButton.addEventListener("click", function () {
        const activityList = document.getElementById("activityList");

        if (activityList) {
            activityList.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
        }
    });
}


