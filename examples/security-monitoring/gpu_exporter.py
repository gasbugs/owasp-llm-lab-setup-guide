import csv
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO


QUERY = [
    "nvidia-smi",
    "--query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu",
    "--format=csv,noheader,nounits",
]


def metrics() -> str:
    completed = subprocess.run(QUERY, check=True, capture_output=True, text=True, timeout=5)
    lines = [
        "# HELP llm_gpu_exporter_up Whether the NVIDIA query completed successfully.",
        "# TYPE llm_gpu_exporter_up gauge",
        "llm_gpu_exporter_up 1",
    ]
    fields = (
        ("llm_gpu_utilization_percent", "GPU utilization percentage"),
        ("llm_gpu_memory_used_mib", "GPU framebuffer memory used in MiB"),
        ("llm_gpu_memory_total_mib", "Total GPU framebuffer memory in MiB"),
        ("llm_gpu_temperature_celsius", "GPU temperature in Celsius"),
    )
    for metric, help_text in fields:
        lines.extend((f"# HELP {metric} {help_text}", f"# TYPE {metric} gauge"))
    for row in csv.reader(StringIO(completed.stdout)):
        index, name, utilization, memory_used, memory_total, temperature = (item.strip() for item in row)
        labels = f'gpu="{index}",model="{name}"'
        lines.extend(
            (
                f"llm_gpu_utilization_percent{{{labels}}} {utilization}",
                f"llm_gpu_memory_used_mib{{{labels}}} {memory_used}",
                f"llm_gpu_memory_total_mib{{{labels}}} {memory_total}",
                f"llm_gpu_temperature_celsius{{{labels}}} {temperature}",
            )
        )
    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/healthz":
            body = b'{"ok":true,"exporter":"nvidia-smi"}\n'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/metrics":
            try:
                body = metrics().encode()
                self.send_response(200)
            except (OSError, subprocess.SubprocessError, ValueError) as error:
                body = f"llm_gpu_exporter_up 0\n# {type(error).__name__}\n".encode()
                self.send_response(503)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
        else:
            body = b"not found\n"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9400), Handler).serve_forever()
