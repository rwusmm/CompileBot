CompileBot is a Discord bot that lets you compile and run C and C++ code directly inside Discord. It supports both command-based usage and a simple interactive GUI using buttons and modals.

No external IDE. No switching tabs. Just write, compile, and run.

**Features**:
Compile and run C (C11) and C++ (C++17 or newer)
Interactive GUI with buttons and modals
Custom stdin input support
Output capture with clean formatting
Error and warning display
Time and memory limits for safety
Isolated execution environment
Multi-user safe execution

*How It Works*:
User submits code using:
Slash commands (or !), or
The GUI "Compile" button

CompileBot:
Creates a temporary sandbox
Compiles the code using gcc or g++
Runs the program with optional input
Captures stdout and stderr
Output is returned as a formatted Discord messag

To build the source code you need TDM GCC installed, and Node.js
Run: npm install and after that node bot.js
Copyrighted reserved @2026
