// Safe bridge: expose only the window-mode controls to the renderer.
// contextIsolation is on, so the renderer cannot touch Node/Electron directly.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("appWindow", {
  dock: () => ipcRenderer.invoke("window:dock"),
  float: () => ipcRenderer.invoke("window:float"),
});
