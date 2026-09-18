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
    groups.forEach((group) => tool.add(new Option(group.dataset.tool, group.dataset.tool)));

    function showTask() {
      const group = groups.find((item) => item.dataset.tool === tool.value);
      group.querySelectorAll(".tool-example").forEach((example, index) => {
        example.hidden = index !== task.selectedIndex;
      });
      widget.querySelector(".tool-examples-status").textContent =
        `${tool.value} and syq: ${task.value}.`;
    }
    function showTool() {
      const previous = task.value;
      task.replaceChildren();
      groups.forEach((group) => {
        const selected = group.dataset.tool === tool.value;
        group.hidden = !selected;
        group.open = true;
        group.querySelector("summary").hidden = true;
        if (selected) {
          group.querySelectorAll(".tool-example").forEach((example) => {
            task.add(new Option(example.dataset.title, example.dataset.title));
          });
        }
      });
      if ([...task.options].some((option) => option.value === previous)) task.value = previous;
      showTask();
    }
    tool.addEventListener("change", showTool);
    task.addEventListener("change", showTask);
    showTool();
    controls.hidden = false;
  });
})();
