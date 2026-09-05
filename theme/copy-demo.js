(() => {
  "use strict";

  function tree(rootName, files, before) {
    const root = { children: new Map() };
    const paths = new Set([...Object.keys(files), ...Object.keys(before || {})]);
    for (const path of [...paths].sort()) {
      let node = root;
      const parts = path.split("/");
      parts.forEach((part, index) => {
        if (!node.children.has(part)) node.children.set(part, { children: new Map() });
        node = node.children.get(part);
        if (index === parts.length - 1 && before) {
          node.status = !(path in files) ? "Removed"
            : !(path in before) ? "New"
            : files[path] !== before[path] ? "Updated" : "Kept";
        }
      });
    }
    function branch(node) {
      const list = document.createElement("ul");
      for (const [name, child] of node.children) {
        const item = document.createElement("li");
        const row = document.createElement("span");
        row.className = "copy-demo-entry";
        const label = document.createElement("span");
        label.className = child.children.size ? "copy-demo-folder" : "copy-demo-file";
        label.textContent = name + (child.children.size ? "/" : "");
        row.append(label);
        if (child.status) {
          const badge = document.createElement("span");
          badge.className = "copy-demo-badge copy-demo-" + child.status.toLowerCase();
          badge.textContent = child.status;
          row.append(badge);
        }
        item.append(row);
        if (child.children.size) item.append(branch(child));
        list.append(item);
      }
      return list;
    }
    const wrapper = document.createElement("div");
    wrapper.className = "copy-demo-tree";
    const name = document.createElement("strong");
    name.textContent = rootName;
    wrapper.append(name, branch(root));
    return wrapper;
  }

  document.querySelectorAll(".copy-demo").forEach(async (demo, index) => {
    try {
      const response = await fetch(demo.dataset.examples);
      if (!response.ok) return;
      const data = await response.json();
      const controls = demo.querySelector(".copy-demo-controls");
      const group = document.createElement("fieldset");
      const legend = document.createElement("legend");
      legend.textContent = "Choose a command";
      group.append(legend);
      const choices = document.createElement("div");
      choices.className = "copy-demo-choices";
      group.append(choices);
      demo.querySelector(".copy-demo-source pre").replaceWith(tree("project/", data.source));
      demo.querySelector(".copy-demo-before pre").replaceWith(tree("/backup/", data.before));
      const after = demo.querySelector(".copy-demo-after");
      function show(example) {
        demo.querySelector(".copy-demo-command code").textContent = example.command;
        demo.querySelector(".copy-demo-description").textContent = example.description;
        const previous = after.querySelector("pre, .copy-demo-tree");
        previous.replaceWith(tree("/backup/", example.after, data.before));
        demo.dataset.selected = example.id;
      }
      data.examples.forEach((example, i) => {
        const label = document.createElement("label");
        const input = document.createElement("input");
        input.type = "radio";
        input.name = "copy-example-" + index;
        input.value = example.id;
        input.checked = i === 0;
        input.addEventListener("change", () => { if (input.checked) show(example); });
        label.append(input, document.createTextNode(example.title));
        choices.append(label);
      });
      show(data.examples[0]);
      controls.append(group);
      controls.hidden = false;
    } catch {
      // The static first example remains readable when the asset is unavailable.
    }
  });
})();
