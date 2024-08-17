# PertaPack
Plugin to encrypt game assets without needing access to game source code.
## Table of Contents

1. [Build](#build)
2. [Usage](#usage)
3. [Contributing](#contributing)

## Build
Compiles with Visual Studio 2022.
## Usage
Copy all DLL files and inject `pertapack.dll`. You can do so with any DLL injector or by using LoadLibrary:
   ```cpp
   LoadLibraryA("pertapack.dll");
   ```
## Contributing
1. **Fork the repository**.
   ```bash
   git clone https://github.com/doomertheboomer/pertapack
   ```
2. **Create a new branch**:
   ```bash
   git checkout -b feature/your-feature
   ```

3. **Make your changes**.

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Add your commit message"
   ```

5. **Push to the branch**:
   ```bash
   git push origin feature/your-feature
   ```

6. **Open a Pull Request**.
