await (async () => {
  const check = (condition, message) => {
    if (!condition) throw new Error(message);
  };
  const marker = () => document.querySelector("#lab05-marker-target")
    .getAttribute("data-lab05-marker");
  const id = document.querySelector("#incident-id").value.trim();
  check(id.length > 0, "Enter the fixture Guid");
  check(marker() === null, "Reload before test");
  const response = await fetch(`/api/incidents/${encodeURIComponent(id)}`);
  check(response.status === 200, `Unexpected HTTP ${response.status}`);
  const comments = (await response.json()).comments ?? [];
  check(comments.some(c => c.text.includes("data-lab05-marker")), "Wrong fixture");
  await load();
  await load();
  const box = document.querySelector("#comments");
  check(box.children.length === comments.length, "Comments duplicated or missing");
  comments.forEach((comment, i) => {
    check(box.children[i].textContent === comment.text, `Comment ${i}: text changed`);
    check(box.children[i].childElementCount === 0, `Comment ${i}: data became HTML`);
  });
  await new Promise(resolve => setTimeout(resolve, 500));
  check(marker() === null, "Marker executed");
  console.log("PASS: every comment rendered as plain text, no duplicates after re-render");
})();