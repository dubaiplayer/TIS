// Electron main process. Creates the window and implements the two window modes:
//   - "float": a normal, movable floating window (default)
//   - "dock":  docked to the right screen edge, full work-area height, always-on-top
// Toggling is driven from the renderer over IPC (see preload.cjs).
const { app, BrowserWindow, ipcMain, screen } = require("electron");
const path = require("path");

const DEV = process.env.ELECTRON_DEV === "1";
const DOCK_WIDTH = 440;
const FLOAT_SIZE = { width: 900, height: 720 };

let win = null;

function createWindow() {
  win = new BrowserWindow({
    width: FLOAT_SIZE.width,
    height: FLOAT_SIZE.height,
    minWidth: 380,
    title: "Phishing Analyzer",
    backgroundColor: "#0f1419",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  if (DEV) {
    win.loadURL("http://localhost:5173");
  } else {
    win.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }
}

function dockRight() {
  if (!win) return;
  const { workArea } = screen.getPrimaryDisplay();
  win.setAlwaysOnTop(true, "floating");
  win.setResizable(true);
  win.setBounds({
    x: workArea.x + workArea.width - DOCK_WIDTH,
    y: workArea.y,
    width: DOCK_WIDTH,
    height: workArea.height,
  });
}

function floatMode() {
  if (!win) return;
  win.setAlwaysOnTop(false);
  win.setResizable(true);
  win.setBounds({
    width: FLOAT_SIZE.width,
    height: FLOAT_SIZE.height,
    x: undefined,
    y: undefined,
  });
  win.center();
}

ipcMain.handle("window:dock", () => { dockRight(); return "dock"; });
ipcMain.handle("window:float", () => { floatMode(); return "float"; });

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
