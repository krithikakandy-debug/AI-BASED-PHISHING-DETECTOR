const BACKEND_URL = "http://localhost:3000";

function getActiveTabUrl(callback) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    callback(tab && tab.url && tab.url.startsWith("http") ? tab.url : null);
  });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    chrome.runtime.sendMessage({ type: "URL_UPDATED", url: tab.url }).catch(() => {});
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (tab && tab.url && tab.url.startsWith("http")) {
      chrome.runtime.sendMessage({ type: "URL_UPDATED", url: tab.url }).catch(() => {});
    }
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_CURRENT_URL") {
    getActiveTabUrl((url) => sendResponse({ url }));
    return true;
  }

  if (message.type === "ANALYZE_URL") {
    fetch(`${BACKEND_URL}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: message.url })
    })
      .then((res) => res.json())
      .then((data) => sendResponse({ data }))
      .catch(() => sendResponse({ error: true }));
    return true;
  }
});

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(console.error);
