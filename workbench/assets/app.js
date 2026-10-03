"use strict";
const byId = (id) => document.getElementById(id);
let data;
let strategy = "recent";
let selected;
let decision = "pending";
let position = 3;
const severityOf = (alert) => alert["kibana.alert.rule.parameters.severity"];
const frame = () => data.frames[position - 1];
const contains = (mode, id) => frame()[mode].some((item) => item.id === id);
const verdicts = {
  recent:
    "The selected window has no controller integrity record. Check the complete alert history before closing this review.",
  retained:
    "The selected window includes a controller program change. Confirm the maintenance record before treating the change as authorized.",
};

function renderDetail() {
  const alert = data.alerts.find((item) => item.id === selected);
  const retained = contains(strategy, selected);
  const detail = byId("detail");
  detail.replaceChildren();
  const id = document.createElement("span");
  id.className = "evidence-id";
  id.textContent = `${alert.id} / ${severityOf(alert).toUpperCase()}`;
  const title = document.createElement("h2");
  title.id = "evidence-title";
  title.textContent = alert.rule;
  const list = document.createElement("dl");
  for (const [label, value] of [
    ["Asset", alert.asset],
    ["Observed record (fictional)", alert.evidence],
    [
      "Selection trace",
      retained
        ? strategy === "retained" && !contains("recent", selected)
          ? "Included from the severity reserve. Recency alone excludes this record."
          : "Included as a recent alert in the remaining context slots."
        : data.alerts.indexOf(alert) >= position
          ? "Not yet arrived at this replay step."
          : contains("recent", selected)
            ? "Displaced by the reserve in this replay step."
            : "Outside this context window. The source record remains available to inspect.",
    ],
  ]) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    list.append(dt, dd);
  }
  detail.append(id, title, list);
  byId("raw").textContent = JSON.stringify(alert, null, 2);
}

function render() {
  byId("recent").setAttribute("aria-pressed", String(strategy === "recent"));
  byId("reserve").setAttribute("aria-pressed", String(strategy === "retained"));
  byId("position").textContent =
    `${position} / ${data.alerts.length} alerts arrived`;
  byId("previous").disabled = position === 1;
  byId("next").disabled = position === data.alerts.length;
  byId("used").textContent = frame()[strategy].length;
  byId("explanation").textContent = contains(strategy, "A-017")
    ? contains("recent", "A-017")
      ? "The critical record is recent enough to fit under both strategies. Advance the shift to see the window move."
      : "The reserve holds the older critical record. A newer record gives up its slot. Selection is returned newest first."
    : "The three newest alerts fill every slot. The older critical record is outside the analyst’s context.";
  byId("alerts").replaceChildren();
  for (const alert of data.alerts) {
    const retained = contains(strategy, alert.id);
    const future = data.alerts.indexOf(alert) >= position;
    const button = document.createElement("button");
    button.className = `alert${retained ? " kept" : ""}${selected === alert.id ? " selected" : ""}`;
    button.setAttribute("aria-pressed", String(selected === alert.id));
    button.setAttribute(
      "aria-label",
      `${alert.id}, ${alert.rule}, ${severityOf(alert)}, ${retained ? "in context" : future ? "not yet arrived" : "outside context"}`,
    );
    const time = document.createElement("span");
    time.className = "time";
    time.textContent = alert["@timestamp"].slice(11, 16);
    const name = document.createElement("span");
    name.className = "alert-name";
    name.textContent = alert.rule;
    const id = document.createElement("span");
    id.className = "alert-id";
    id.textContent = `${alert.id} · ${retained ? "IN CONTEXT" : future ? "NOT YET ARRIVED" : "OUTSIDE"}`;
    name.append(id);
    const severity = document.createElement("span");
    severity.className = `severity ${severityOf(alert)}`;
    severity.textContent = severityOf(alert).toUpperCase();
    button.append(time, name, severity);
    button.addEventListener("click", () => {
      selected = alert.id;
      render();
      byId("alerts").querySelector(`[aria-label^="${selected},"]`).focus();
    });
    byId("alerts").append(button);
  }
  renderDetail();
  byId("verdict").textContent =
    decision === "discarded"
      ? ""
      : verdicts[contains(strategy, "A-017") ? "retained" : "recent"];
  byId("decision").textContent =
    decision === "pending"
      ? "Awaiting your review"
      : decision === "kept"
        ? "Sample verdict kept in this page."
        : "Sample verdict discarded in this page.";
}

for (const [id, delta] of [
  ["previous", -1],
  ["next", 1],
]) {
  byId(id).addEventListener("click", () => {
    position += delta;
    decision = "pending";
    render();
  });
}

for (const [id, mode] of [
  ["recent", "recent"],
  ["reserve", "retained"],
]) {
  byId(id).addEventListener("click", () => {
    strategy = mode;
    decision = "pending";
    render();
  });
}
byId("keep").addEventListener("click", () => {
  decision = "kept";
  render();
});
byId("discard").addEventListener("click", () => {
  decision = "discarded";
  render();
});
byId("reset").addEventListener("click", () => {
  strategy = "recent";
  selected = data.alerts[0].id;
  decision = "pending";
  position = 3;
  render();
  byId("recent").focus();
});

async function load() {
  byId("error").hidden = true;
  byId("loading").hidden = false;
  try {
    const response = await fetch("/api/case");
    if (!response.ok)
      throw new Error(
        "The local case endpoint did not return a valid response.",
      );
    data = await response.json();
    if (
      data.synthetic !== true ||
      data.capacity !== 3 ||
      !Array.isArray(data.alerts) ||
      data.alerts.length < 3 ||
      !Array.isArray(data.frames) ||
      data.frames.length !== data.alerts.length
    ) {
      throw new Error("The synthetic case is incomplete.");
    }
    selected = data.alerts[0].id;
    byId("total").textContent = `${data.alerts.length} alerts`;
    render();
    byId("case").hidden = false;
  } catch (error) {
    byId("case").hidden = true;
    const message = document.createElement("p");
    message.textContent = `${error.message} Check the terminal and restart the local workbench, then retry.`;
    const retry = document.createElement("button");
    retry.textContent = "Retry loading case";
    retry.addEventListener("click", load);
    byId("error").replaceChildren(message, retry);
    byId("error").hidden = false;
  } finally {
    byId("loading").hidden = true;
  }
}
load();
