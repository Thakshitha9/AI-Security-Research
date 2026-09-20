// ================================
// AI SECURITY PLATFORM
// Dashboard Interactions
// ================================

// Sidebar navigation
const navItems = document.querySelectorAll(".nav-item");

navItems.forEach((item) => {
    item.addEventListener("click", function (event) {
        event.preventDefault();

        navItems.forEach((nav) => {
            nav.classList.remove("active");
        });

        this.classList.add("active");
    });
});


// Quick action buttons
const quickActions = document.querySelectorAll(".quick-action");

quickActions.forEach((button) => {
    button.addEventListener("click", function () {

        const actionName =
            this.querySelector("strong")?.textContent || "Security Action";

        console.log(`${actionName} selected`);

        alert(`${actionName} module will be connected to the backend soon.`);
    });
});


// View All button
const viewButton = document.querySelector(".view-button");

if (viewButton) {
    viewButton.addEventListener("click", function () {
        alert("Full security activity will be available here.");
    });
}


// Display current time
function updateTime() {

    const now = new Date();

    console.log(
        "Dashboard active:",
        now.toLocaleTimeString()
    );
}

updateTime();


// Refresh the time every minute
setInterval(updateTime, 60000);