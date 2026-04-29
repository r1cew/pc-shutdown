import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";
import "./App.css";

function App() {
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);
  const [hasError, setHasError] = useState(false);

  const handleShutdown = async () => {
    setLoading(true);
    setHasError(false);
    setStatus("Поиск ПК в сети...");

    try {
      const result = await invoke<string>("shutdown_pc");
      setStatus(result);
    } catch (error) {
      setHasError(true);
      setStatus(String(error));
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="shell">
      <section className="panel">
        <div className="eyebrow">LAN shutdown</div>

        <button
          onClick={handleShutdown}
          disabled={loading}
          className={`shutdown-btn ${loading ? "loading" : ""}`}
        >
          <span className="button-kicker">
            {loading ? "Подключение" : "Удаленная команда"}
          </span>
          <span className="button-label">
            {loading ? "Выполняется..." : "Выключить"}
          </span>
        </button>

        <div className={`status ${hasError ? "error" : "success"} ${status ? "visible" : ""}`}>
          {status || "Готово к поиску сервера"}
        </div>
      </section>
    </main>
  );
}

export default App;
