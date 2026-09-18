(() => {
  "use strict";

  document.querySelectorAll(".tool-examples").forEach((widget, index) => {
    const groups = [...widget.querySelectorAll(".tool-examples-group")];
    const controls = widget.querySelector(".tool-examples-controls");
    function chooser(title) {
      const label = document.createElement("label");
      const text = document.createElement("span");
      text.textContent = title;
      text.id = `tool-example-${index}-${title.replaceAll(" ", "-")}`;
      const select = document.createElement("select");
      select.setAttribute("aria-labelledby", text.id);
      label.append(text, select);
      controls.append(label);
      return select;
    }
    const tool = chooser("Your tool");
    const task = chooser("Your task");
    groups.filter((group) => group.dataset.tool !== "syq")
      .forEach((group) => tool.add(new Option(group.dataset.tool, group.dataset.tool)));

    const examples = groups.map((group) => ({
      group,
      tool: group.dataset.tool,
      tasks: [...group.querySelectorAll(".tool-example")],
    }));
    for (const [label, syqOnly] of [["Compare familiar tasks", false], ["More with syq", true]]) {
      const group = document.createElement("optgroup");
      group.label = label;
      const titles = new Set(examples.filter((item) => (item.tool === "syq") === syqOnly)
        .flatMap((item) => item.tasks.map((entry) => entry.dataset.title)));
      titles.forEach((title) => group.append(new Option(title, title)));
      task.append(group);
    }

    function update() {
      function available(name, title) {
        return examples.some((item) => (item.tool === name || item.tool === "syq") &&
          item.tasks.some((entry) => entry.dataset.title === title));
      }
      for (const option of tool.options) {
        option.disabled = !available(option.value, task.value);
      }
      for (const option of task.options) {
        option.disabled = !available(tool.value, option.value);
      }
      examples.forEach((item) => {
        item.group.hidden = (item.tool !== tool.value && item.tool !== "syq") ||
          !item.tasks.some((entry) => entry.dataset.title === task.value);
        item.group.open = true;
        item.group.querySelector("summary").hidden = true;
        item.tasks.forEach((entry) => {
          entry.hidden = entry.dataset.title !== task.value;
        });
      });
      const syqOnly = examples.some((item) => item.tool === "syq" &&
        item.tasks.some((entry) => entry.dataset.title === task.value));
      widget.querySelector(".tool-examples-status").textContent =
        syqOnly ? `More with syq: ${task.value}.` : `${tool.value} and syq: ${task.value}.`;
    }
    tool.addEventListener("change", update);
    task.addEventListener("change", update);
    update();
    controls.hidden = false;
    widget.querySelector(".tool-examples-hint").hidden = false;
  });
})();
