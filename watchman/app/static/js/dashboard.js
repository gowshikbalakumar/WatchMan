const packetBody = document.getElementById("packetBody");
const filterInput = document.getElementById("filterInput");

async function callApi(path, options = {}) {
  const res = await fetch(path, options);
  return await res.json();
}

async function refresh() {
  const filter = encodeURIComponent(filterInput.value.trim());
  const data = await callApi(`/api/packets?filter=${filter}`);
  const stats = await callApi("/api/stats");

  document.getElementById("totalPackets").innerText = stats.captured_packets;
  document.getElementById("suspiciousPackets").innerText = stats.suspicious_packets;

  packetBody.innerHTML = "";
  data.packets.slice(0, 100).forEach((pkt) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${pkt.timestamp}</td>
      <td>${pkt.src_ip}:${pkt.src_port || "-"}</td>
      <td>${pkt.dst_ip}:${pkt.dst_port || "-"}</td>
      <td>${pkt.protocol}</td>
      <td>${pkt.length}</td>
      <td>${pkt.summary}</td>
      <td class="${pkt.suspicious ? "alert" : ""}">${pkt.reason || ""}</td>
    `;
    packetBody.appendChild(tr);
  });
}

document.getElementById("startBtn").onclick = () => callApi("/api/sniffer/start", { method: "POST" });
document.getElementById("stopBtn").onclick = () => callApi("/api/sniffer/stop", { method: "POST" });
document.getElementById("refreshBtn").onclick = refresh;

setInterval(refresh, 4000);
refresh();
