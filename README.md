<p align="center">
    <img src="https://raw.githubusercontent.com/sh2dow/MW05RecompResources/refs/heads/main/images/logo/Logo.png" width="512"/>
</p>

---

### **NFS MW '05 is an unofficial PC port of the Xbox 360 version.**
### Note: The project is based on [Unleashed Recompiled](https://github.com/hedge-dev/UnleashedRecomp) 
## **[Curently in development]**

**This project does not include any game assets. You must provide the files from your own legally acquired copy of the game to install or build NFS MW '05.**

[Check out the latest release here](https://github.com/sh2dow/MW05Recomp/releases/latest).

[XenonRecomp](https://github.com/sh2dow/XenonRecomp) and [XenosRecomp](https://github.com/sh2dow/XenosRecomp) are the main recompilers used for converting the game's original PowerPC code and Xenos shaders into compatible C++ and HLSL code respectively. The development of these recompilers was directly inspired by [N64: Recompiled](https://github.com/N64Recomp/N64Recomp), which was used to create [Zelda 64: Recompiled](https://github.com/Zelda64Recomp/Zelda64Recomp).

## Table of Contents

- [Minimum System Requirements](#minimum-system-requirements)
- [How to Install](#how-to-install)
- [Features](#features)
- [FAQ](#faq)
- [Building](#building)
- [Debugging](#debugging)
- [Credits](#credits)

## Minimum System Requirements

- CPU with support for the AVX instruction set:
  - Intel: Sandy Bridge (Intel Core 2nd Generation)
  - AMD: Bulldozer (AMD FX series)
- GPU with support for Direct3D 12.0 (Shader Model 6) or Vulkan 1.2:
  - NVIDIA: GeForce GT 630 (Kepler)
  - AMD: Radeon HD 7750 (2012, not the RX 7000)
  - Intel: HD Graphics 510 (Skylake)
- Memory:
  - 8 GB minimum
- Operating System:
  - Windows 10 (version 1909)
  - A modern Linux distro such as Ubuntu 22.04 LTS
- Storage:
  - With DLC: 10 GiB required
  - Without DLC: 6 GiB required

> [!NOTE]
> More storage space may be required if uncompressed game files are provided during installation.

## How to Install

- The installation process is nearly similar to Unleashed Recompiled (Installer runner is currently disabled for this project)

1) You must have access to the following:

    - Xbox 360 (modifications not necessary)
    - Xbox 360 Storage Device (either an Xbox 360 hard drive or an external USB storage device)
    - Xbox 360 Hard Drive Transfer Cable or a compatible SATA to USB adapter (only required for dumping from an Xbox 360 hard drive)
    - NFS MW '05 for Xbox 360 (EU)
        - Retail Disc or Digital Copy.
        
> [!TIP]
> If you do not have the Xbox 360 Hard Drive Transfer Cable, please ensure that you purchase the correct revision of it for your console.
>
> The latest revision works with both original Xbox 360 and Xbox 360 S|E hard drives, but the first revision only works with original Xbox 360 hard drives.
>
> To know which is which, the first revision cable is gray, whereas the latest revision (which supports any Xbox 360 hard drive) is black.

2) **Before proceeding with the installation**, make sure to follow the guide on how to acquire the game files from your Xbox 360.

    - Xbox 360 Hard Drive Dumping Guide
        - [English](/docs/DUMPING-en.md)
    - Xbox 360 USB Dumping Guide
        - [English](/docs/DUMPING-USB-en.md)

3) Download [the latest release](https://github.com/sh2dow/MW05Recomp/releases/latest) of MW05 Recompiled and extract it to where you'd like the game to be installed.

4) Run the executable and you will be guided through the installation process. You will be asked to provide the files you acquired in the previous step. When presented with options for how to do this:

    - **Add Files** will only allow you to provide **containers or images dumped from an Xbox 360**. These often come in the form of very large files without associated extensions. Don't worry if you're not aware of what's inside of them, the installer will automatically detect what type of content is inside the container.

    - **Add Folder** will only allow you to provide a **directory with the game's raw files** corresponding to the piece of content that is requested. **It will NOT scan your folder for compatible content!**


## Features


### Code Modding

Modifying the code of a recompilation is a fundamentally different process than doing it for a game that only supports one platform on a single executable version. Everyone can build and fork MW05 Recompiled on their own, which makes the method of targeting a single executable essentially impossible.

A convenient and maintainable method for code modding is under research and will come in a future update, which will work consistently across all the platforms that MW05 Recompiled currently supports.

In the meantime, those interested in doing extensive code modding are recommended to fork the repository and introduce their changes in preparation for the code modding update.

## Known Issues


## FAQ

---

You can change the keyboard bindings by editing `config.toml` located in the [configuration directory](#where-is-the-save-data-and-configuration-file-stored), although using a controller is highly recommended until [Action Remapping](#action-remapping) is added in a future update.

Refer to the left column of [this enum template](https://github.com/sh2dow/MW05Recomp/blob/main/UnleashedRecomp/user/config.cpp#L40) for a list of valid keys.

### Where is the save data and configuration file stored?

The save data and configuration files are stored at the following locations:

- Windows: `%APPDATA%\MW05Recomp\`
- Linux: `~/.config/MW05Recomp/`

You will find the save data under the `save` folder (or `mlsave`, if using Hedge Mod Manager's save file redirection). The configuration file is named `config.toml`.

### How can I install mods?

- Currently feature is not implemented

### How can I force the game to run under X11 or Wayland?

Use either of the following arguments to force SDL to run under the video driver you want:

- X11: `--sdl-video-driver x11`
- Wayland: `--sdl-video-driver wayland`

The second argument will be passed directly to SDL as a hint to try to initialize the game with your preferred option.

### How can I improve performance?

You can lower the values of some of the following graphics options to improve performance. Other options may help, but these usually have the biggest impact:

- Resolution Scale
- Anti-Aliasing
- Shadow Resolution

If you want a detailed performance report along with relevant system information, press F1 to view multiple performance graphs. This will aid in the process of gathering as much information as possible in order to identify the problem.

When using a system with multiple GPUs (such as a gaming laptop), please make sure that the game has chosen your dedicated graphics adapter and not your integrated one. The F1 menu will display which device has been selected by its name along with other options that might be available. If you're unable to get the game to select the correct device, you can attempt to override this by changing the `GraphicsDevice` property in `config.toml`. The name of the device must be an exact match.

Some of the game's more demanding sections require strong CPU single-thread performance. While the recompilation process adds minimal CPU overhead, modern hardware is typically bottlenecked by this factor before the GPU.

Linux has an unexpected advantage when it comes to CPU performance, showing improvements in CPU-bound scenarios. It's currently speculated that this could be due to the heavy amount of thread synchronization the game performs, an operation that is likely to be more performant on Linux's CPU scheduler than on Windows' scheduler. If you wish to gain some additional performance, playing on Linux instead of Windows could yield better results.

> [!WARNING]
> Using external frame rate limiters or performance overlays may degrade performance or have negative consequences.

### Can I install the game with a PlayStation 3 copy?

**You cannot use the files from the PlayStation 3 version of the game.** Supporting these files would require an entirely new recompilation, as they have proprietary formatting that only works on PS3 and the code for these formats is only present in that version. All significant differences present in the PS3 version of the game have been included in this project as options.

### Why is the game detecting my PlayStation controller as an Xbox controller?

If you're using a third-party input translation layer (such as DS4Windows or Steam Input), it is recommended that you disable these for full controller support.

### Will macOS be supported?

While macOS is not currently on the roadmap, this project welcomes any effort to add support for this platform. MW05 Recompiled relies on [plume](https://github.com/renderbag/plume), a rendering hardware abstraction layer that will be getting support for Metal in the near future. You can join the macOS discussion on [this issue](https://github.com/sh2dow/MW05Recomp/issues/455).

### What other platforms will be supported?

This project does not plan to support any more platforms other than Windows, Linux and potentially macOS at the moment. Any contributors who wish to support more platforms should do so through a fork.

## Building

Default is MSVC compiler:
### ``pwsh ./build_cmd.ps1``
or
### ``pwsh ./build_cmd.ps1 -Stage all -Config Release -Clean``

For Clang use build switcher:

### Clang (clang-cl), x64, Debug, with an extra CMake flag
``pwsh ./build_switch.ps1 -Compiler Clang -Arch x64 -Config Release -CMakeArgs "-DUSE_IMGUI=ON"``

### MSVC, x64, Release
``pwsh ./build_switch.ps1 -Compiler MSVC -Arch x64 -Config Release``


## Debugging

``pwsh $env:MW05_FORCE_PRESENT=0;$env:MW05_KICK_VIDEO=0;$env:MW05_AUTO_VIDEO=1;$env:MW05_VBLANK_PUMP=1;$env:MW05_VBLANK_CB=1;$env:MW05_PUMP_EVENTS=0;$env:MW05_LIST_SHIMS=0;$env:MW05_BREAK_82813514=0;$env:MW05_FAST_BOOT=0;$env:MW05_TRACE_KERNEL=1;$env:MW05_HOST_TRACE_IMPORTS=1;$env:MW05_HOST_TRACE_HOSTOPS=1;$env:MW_VERBOSE=0;.\Mw05Recomp.exe``
or
``pwsh.exe -Command '$log='"'run_log.txt'; if (Test-Path "'$log) { Remove-Item $log }; $psi = [System.Diagnostics.ProcessStartInfo]::new(); `
$psi.FileName = '"'Mw05Recomp.exe''; "'; `
$psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; `
$envTable = @{MW05_FORCE_PRESENT='"'0';MW05_KICK_VIDEO='1';MW05_AUTO_VIDEO='1';MW05_VBLANK_PUMP='1';MW05_VBLANK_CB='1';MW05_PUMP_EVENTS='0';MW05_LIST_SHIMS='0';MW05_BREAK_82813514='0';MW05_FAST_BOOT='0';MW05_TRACE_KERNEL='0';MW05_HOST_TRACE_IMPORTS='1';MW05_HOST_TRACE_HOSTOPS='1';MW_VERBOSE='0'}; foreach("'$k
        in $envTable.Keys){ $psi.Environment[$k] = $envTable[$k] }; $proc = [System.Diagnostics.Process]::Start($psi); Start-Sleep -Seconds 30; if (!$proc.HasExited) { $proc.Kill() }; $stdout = $proc.StandardOutput.ReadToEnd(); $stderr = $proc.StandardError.ReadToEnd(); Set-Content $log $stdout; if
        ($stderr) { Add-Content $log '"'--- STDERR ---'; Add-Content "'$log $stderr }; $proc.ExitCode'``

### Special Thanks
- [Mr-Wiseguy](https://github.com/Mr-Wiseguy): Creator of [N64: Recompiled](https://github.com/N64Recomp/N64Recomp), which was the inspiration behind the creation of this project. Provided information and assistance at the beginning of development.

- [xenia-project](https://github.com/xenia-project/xenia): Extraordinary amounts of research regarding the inner workings of the Xbox 360, which sped up the development of the recompilation.

- [Katlin Daigler](https://katlindaigler.carbonmade.com): Provided consultation for logo design.

- [ocornut](https://github.com/ocornut): Creator of [Dear ImGui](https://github.com/ocornut/imgui), which is used as the backbone of the custom menus.

- Raymond Chen: Useful resources on Windows application development with his blog ["The Old New Thing"](https://devblogs.microsoft.com/oldnewthing/).

- ### Unleashed Recompiled Team (since MW05 Recompiled is based on Unleashed Recompiled):

- [Skyth](https://github.com/blueskythlikesclouds): Creator and Lead Developer of the recompilation, as well as the developer of technologies created for it such as [XenonRecomp](https://github.com/hedge-dev/XenonRecomp) and [XenosRecomp](https://github.com/hedge-dev/XenosRecomp). Other responsibilities include the creation of the graphics and audio backends for the project, alongside custom menus, dynamic UI aspect ratio and various patches and new features added to the game.

- [Sajid](https://github.com/Sajidur78): Co-creator and Developer of the recompilation, as well as the developer of [XenonAnalyse](https://github.com/hedge-dev/XenonRecomp/?tab=readme-ov-file#XenonAnalyse). Other responsibilities include the implementation of core components for the project, like the Xbox 360 kernel translation layer used to make the game function.

- [Hyper](https://github.com/hyperbx): Developer of system level features, such as achievement support and the custom menus, alongside various other patches and features to make the game feel right at home on modern systems. Aided in the creation of concept art and the final options menu thumbnails.

- [Darío](https://github.com/DarioSamo): Creator of the graphics hardware abstraction layer [plume](https://github.com/renderbag/plume), used by the project's graphics backend. Alongside providing consultation for graphics and aiding with shader research and development, other responsibilities include the installer wizard and Linux support. Provided Spanish localization for the custom menus.

- [ĐeäTh](https://github.com/DeaTh-G): Supervisor of game accurate design philosophy regarding the custom menus. Aided in the implementation of annotation support for Japanese localization, whilst providing minor support for all localization.

- [RadiantDerg](https://github.com/RadiantDerg): Lead Artist behind the thumbnails used in the options menu. Other responsibilities include the creation of several debugging related codes for Hedge Mod Manager and providing aid with the research of the game's internals.

- [PTKay](https://github.com/PTKay): Lead Concept Artist for the custom menus. Aided in the development of the installer wizard's visuals.

- [SuperSonic16](https://github.com/thesupersonic16): Lead Developer of [Hedge Mod Manager](https://github.com/thesupersonic16/HedgeModManager), providing compatibility for modding with the recompilation. Aided in the creation of the deployment system for Linux builds.

- [NextinHKRY](https://github.com/NextinMono): Aided in researching the game's internals and creating concept art for some options menu thumbnails used in the final release. Provided Italian localization for the custom menus.

- [LadyLunanova](https://linktr.ee/ladylunanova): Artist behind the achievement trophy sprite and the keyboard and mouse icons used in the installer wizard.

- [LJSTAR](https://github.com/LJSTARbird): Artist behind the project logo, along with several thumbnail designs used in the options menu and created new icons for the button guide for opening the achievements menu. Provided French localization for the custom menus.

- [saguinee](https://twitter.com/saguinee): Artist behind thumbnail designs used in the options menu such as Hints and Battle Theme.

- [Goalringmod27](https://linktr.ee/goalringmod27): Concept Artist behind the achievements overlay shown during gameplay. Aided in the creation of the Transparency Anti-Aliasing thumbnail.

- [M&M](https://github.com/ActualMandM): Provisional support for dynamic UI aspect ratio.

- [DaGuAr](https://twitter.com/TheDaguar): Provided Spanish localization for the custom menus alongside Darío.

- [brianuuuSonic](https://github.com/brianuuu): Provided Japanese localization for the custom menus.

- [Kitzuku](https://github.com/Kitzuku): Provided German localization for the custom menus.
