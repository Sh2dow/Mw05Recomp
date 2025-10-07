---

# 🧠 NULL Function Pointer Crash — Summary

## ✅ Status: **FIXED**

The crash has been successfully resolved by:

1. 🛠 **Adding** `sub_825968B0` to `invalid_instructions` in `MW05.toml`

    * Prevents the recompiler from generating code for this function
2. 🔁 **Using the existing `PPC_FUNC` replacement** in `mw05_trace_shims.cpp`

    * The shim now handles all calls to this function
    * Prevents **NULL function pointer dereferences**

---

## 🧾 Evidence of Success

| ✅ Checkpoint            | Result                                                                |
| ----------------------- | --------------------------------------------------------------------- |
| Application uptime      | Runs for **30+ seconds** without crashing                             |
| Validation              | No `NULL-CALL` validation messages                                    |
| Stability               | No access violation errors                                            |
| Shim activity           | `[SHIM-ENTRY] sub_825968B0 lr=82596110 r3=00000000` visible in stderr |
| Initialization progress | XAM content creation, SDL init, memory alloc, threads, XEX loading    |

---

## 🧩 Current State

MW05 is now **running stably** and has progressed through:

* 🧱 **XAM Content System Initialization**
* 🖥 **SDL Video Driver Initialization** → `"windows"`
* 💾 **Physical Memory Allocation** → `0x15900000` bytes
* 🧵 **Thread Creation** → two additional threads

    * `0x828508A8`
    * `0x82812ED0`
* 📦 **XEX Module Loading**

  ```
  loadAddress = 0x82000000  
  imageSize   = 0x00CD0000  
  entry       = 0x8262E9A8
  ```

---

## 🚧 Next Steps

Although the crash is resolved, **MW05 halts further progression**.
It’s likely **waiting** on one of the following:

* ⚙️ GPU initialization
* 🧠 Other subsystem setup
* 🎮 Pending user input

Continue investigating **post-initialization flow** to determine the blocking subsystem.

---
