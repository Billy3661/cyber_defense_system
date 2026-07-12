const totalSteps = window.TOTAL_STEPS;
let completedSteps = 0;

function markStepDone(stepNum, total) {
    const stepCard = document.getElementById("step" + stepNum);
    const stepNumEl = document.getElementById("stepNum" + stepNum);
    const doneBtn = document.getElementById("stepDoneBtn" + stepNum);

    if (stepCard.classList.contains("step-done")) return;

    stepCard.classList.add("step-done");
    stepCard.classList.remove("step-active");
    stepNumEl.textContent = "✓";
    stepNumEl.classList.add("done");
    doneBtn.textContent = "✓ Done";
    doneBtn.disabled = true;

    completedSteps++;
    const pct = Math.round((completedSteps / total) * 100);
    document.getElementById("tsProgressBar").style.width = pct + "%";
    document.getElementById("tsProgressLabel").textContent = `Step ${completedSteps} of ${total} completed`;

    const nextStep = document.getElementById("step" + (stepNum + 1));
    if (nextStep) {
        nextStep.classList.add("step-active");
        nextStep.scrollIntoView({ behavior: "smooth", block: "center" });
    }

    if (completedSteps === total) {
        setTimeout(() => {
            document.getElementById("completionCard").classList.remove("hidden");
            document.getElementById("completionCard").scrollIntoView({ behavior: "smooth" });
        }, 500);
    }
}
