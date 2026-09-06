"""Small Streamlit component that returns learners to the shared lab portal."""

import streamlit.components.v1 as components


def render_portal_home() -> None:
    """Render a same-window link using the hostname visible to the browser."""

    components.html(
        """
        <style>
          body { margin: 0; font-family: system-ui, sans-serif; }
          a { display: inline-flex; align-items: center; min-height: 36px;
              padding: 0 12px; border: 1px solid #94a3b8; border-radius: 7px;
              color: #0f172a; background: #fff; font-weight: 700;
              text-decoration: none; }
          a:hover, a:focus-visible { border-color: #2563eb; color: #1d4ed8; }
        </style>
        <a id="portal-home" href="#" target="_parent">← 홈</a>
        <script>
          const hostname = window.parent.location.hostname;
          document.getElementById('portal-home').href = `http://${hostname}:8080/`;
        </script>
        """,
        height=44,
    )
