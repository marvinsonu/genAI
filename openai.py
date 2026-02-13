import os
import sys


def main():
    # Prevent this file (openai.py) from shadowing the installed openai package.
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path = [p for p in sys.path if os.path.abspath(p or os.getcwd()) != current_dir]

    from openai import OpenAI

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Set OPENAI_API_KEY in your environment before running this script.")
        return

    client = OpenAI(api_key=api_key)
    print("Chatbot started! Type 'exit' to quit.\n")

    messages = [{"role": "system", "content": "You are a helpful assistant."}]

    while True:
        user_input = input("You: ").strip()

        if user_input.lower() == "exit":
            print("Goodbye!")
            break

        if not user_input:
            continue

        messages.append({"role": "user", "content": user_input})

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
        )

        reply = response.choices[0].message.content
        print("Bot:", reply)
        messages.append({"role": "assistant", "content": reply})


if __name__ == "__main__":
    main()
