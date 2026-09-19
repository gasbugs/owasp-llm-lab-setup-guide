"""Replace only the model constructor import in the pinned upstream source."""
import sys
from pathlib import Path


def configure(source):
    old = "from langchain_litellm import ChatLiteLLM"
    new = "from model_client import create_chat_model as ChatLiteLLM"
    if source.count(old) != 1:
        raise ValueError("Expected exactly one upstream ChatLiteLLM import")
    return source.replace(old, new, 1)


if __name__ == "__main__":
    target = Path(sys.argv[1])
    target.write_text(configure(target.read_text(encoding="utf-8")), encoding="utf-8")
