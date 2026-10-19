/* Bộ lọc, tìm kiếm và nhảy tới finding. Không phụ thuộc thư viện; trang vẫn đọc được khi tắt JavaScript. */
(function () {
    "use strict";

    function setupPanel(panel) {
        var filters = panel.querySelector("[data-filters]");
        if (!filters) { return; }
        filters.hidden = false;

        var buttons = filters.querySelectorAll("[data-filter]");
        var input = filters.querySelector("[data-search-input]");
        var items = panel.querySelectorAll("details.finding");
        var groups = panel.querySelectorAll("[data-group]");
        var empty = panel.querySelector("[data-no-match]");
        var level = "all";

        function apply() {
            var query = (input.value || "").trim().toLowerCase();
            var visible = 0;
            items.forEach(function (item) {
                var okLevel = level === "all" || item.getAttribute("data-severity") === level;
                var okText = !query || (item.getAttribute("data-search") || "").indexOf(query) !== -1;
                item.hidden = !(okLevel && okText);
                if (!item.hidden) { visible += 1; }
            });
            groups.forEach(function (group) {
                group.hidden = !group.querySelector("details.finding:not([hidden])");
            });
            if (empty) { empty.hidden = visible !== 0; }
        }

        buttons.forEach(function (button) {
            button.addEventListener("click", function () {
                level = button.getAttribute("data-filter");
                buttons.forEach(function (other) { other.classList.toggle("is-active", other === button); });
                apply();
            });
        });
        input.addEventListener("input", apply);
    }

    function openTarget(id) {
        var target = id && document.getElementById(id);
        if (!target) { return; }
        if (target.tagName === "DETAILS") { target.open = true; }
        target.hidden = false;
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        target.classList.add("is-highlighted");
        window.setTimeout(function () { target.classList.remove("is-highlighted"); }, 1800);
    }

    document.querySelectorAll("[data-findings-panel]").forEach(setupPanel);

    document.querySelectorAll("[data-jump]").forEach(function (link) {
        link.addEventListener("click", function (event) {
            event.preventDefault();
            var id = link.getAttribute("data-jump");
            openTarget(id);
            if (window.history && window.history.replaceState) { window.history.replaceState(null, "", "#" + id); }
        });
    });

    if (window.location.hash.length > 1) { openTarget(window.location.hash.slice(1)); }
})();
