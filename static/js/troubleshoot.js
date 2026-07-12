const searchInput = document.getElementById("tsSearch");
const cards = document.querySelectorAll(".guide-card");
const noResults = document.getElementById("noResults");

searchInput.addEventListener("input", () => {
    const q = searchInput.value.toLowerCase().trim();
    let visible = 0;
    cards.forEach(card => {
        const match = !q || card.dataset.search.includes(q) || card.querySelector(".guide-title").textContent.toLowerCase().includes(q);
        card.style.display = match ? "" : "none";
        if (match) visible++;
    });
    noResults.classList.toggle("hidden", visible > 0);
});
