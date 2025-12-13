
const urlScanForm = document.getElementById("url-scan-form");
const scanResultElem = document.getElementById("scan-result");
const spinnerElem = document.getElementById("scan-spinner");
const scanHistoryTable = document.getElementById("scan-history-table");


if (spinnerElem) {
  spinnerElem.style.display = "none";
}


if (urlScanForm) {
  urlScanForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    const url = document.getElementById("url-to-scan").value;

    if (spinnerElem) {
      spinnerElem.style.display = "inline-block";
    }

    try {
      const response = await fetch("/scan-url", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ url })
      });

      
      if (spinnerElem) {
        spinnerElem.style.display = "none";
      }

      if (!response.ok) {
        scanResultElem.innerText = "Scan failed: Server error";
        return;
      }

      const result = await response.json();

      
      scanResultElem.innerText = `Scan Result: ${result.result}`;

     
      addToScanHistory(result);

    } catch (error) {
      if (spinnerElem) {
        spinnerElem.style.display = "none";
      }
      console.error("Scan failed:", error);
      scanResultElem.innerText = "Scan failed: Network error";
    }
  });
}


function addToScanHistory(scanData) {
  if (!scanHistoryTable) return;

  
  const newRow = document.createElement("tr");
  newRow.innerHTML = `
    <td>${scanData.date}</td>
    <td>${scanData.type}</td>
    <td>${scanData.target}</td>
    <td>${scanData.status}</td>
    <td>${scanData.result}</td>
  `;

  
  scanHistoryTable.insertBefore(newRow, scanHistoryTable.firstChild);

  
  while (scanHistoryTable.rows.length > 3) {
    scanHistoryTable.deleteRow(scanHistoryTable.rows.length - 1); 
  }
}


window.addEventListener("DOMContentLoaded", async () => {
  const res = await fetch("/scan-history");
  const history = await res.json();

  const latestThree = history.slice(-3).reverse(); 
  latestThree.forEach(addToScanHistory);
});

