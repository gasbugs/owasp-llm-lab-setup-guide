"""Use Ollama's native chat transport without changing DVLA's agent or tools."""
import os


def create_chat_model(*, model, temperature=0, streaming=True, **kwargs):
    if model.startswith(("ollama/", "ollama_chat/")):
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=model.split("/", 1)[1],
            base_url=os.environ.get("OLLAMA_API_BASE")
            or os.environ.get("OLLAMA_HOST", "http://ollama:11434"),
            temperature=temperature,
            reasoning=False,
            disable_streaming=not streaming,
            **kwargs,
        )

    from langchain_litellm import ChatLiteLLM

    return ChatLiteLLM(
        model=model, temperature=temperature, streaming=streaming, **kwargs
    )
