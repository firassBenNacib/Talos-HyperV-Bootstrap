# Talos-HyperV-Bootstrap

An interactive PowerShell script for creating and bootstrapping Kubernetes clusters on Talos Linux with Hyper-V.

## Table of Contents

* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Usage](#usage)
* [Commands](#commands)
* [Options](#options)
* [License](#license)
* [Author](#author)

## Prerequisites

* Windows 10 or 11 with **Hyper-V enabled**
* PowerShell 5.1+ run **as Administrator**
* [talosctl](https://www.talos.dev/v1.11/talos-guides/install/talosctl/) installed and on `PATH`
* [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/) installed and on `PATH`

## Installation

Clone:

```powershell
git clone https://github.com/firassBenNacib/Talos-HyperV-Bootstrap.git
cd Talos-HyperV-Bootstrap
````

## Usage

Boot in Talos maintenance mode. The script attaches the ISO for new VMs and downloads it if it’s missing. You can override with `-TalosISO` and `-TalosVersion`.

See the [Talos docs](https://www.talos.dev/v1.11/talos-guides/install/virtualized-platforms/hyper-v/) for more information.

### Quick start

**1) Create VMs (1 control-plane + 1 worker)**

```powershell
.\Talos.ps1 create -Cluster cluster-lab -SwitchName talos
```

**2) Bootstrap**

```powershell
.\Talos.ps1 bootstrap -Cluster cluster-lab
```



**3) Fetch and activate kubeconfig**

```powershell
.\Talos.ps1 kubeconfig -Cluster cluster-lab
```

### Optional Commands

**Merge kubeconfigs**

```powershell
.\Talos.ps1 merge -Cluster cluster-lab-1,cluster-lab-2 -Name homelab
```

Activate the merged set:

```powershell
.\Talos.ps1 kubeconfig -Cluster homelab
```

**VM management**

```powershell
.\Talos.ps1 list -ShowDisk
```

```powershell
.\Talos.ps1 start -All
```

```powershell
.\Talos.ps1 stop -Cluster cluster-lab
```

**Disk operations**

```powershell
.\Talos.ps1 disk -Cluster cluster-lab -ControlPlanesOnly -ResizeDisk 40G
```

```powershell
.\Talos.ps1 disk -Cluster cluster-lab -WorkersOnly -AddDisk 100G
```

**Cleanup**

```powershell
.\Talos.ps1 clean -Cluster cluster-lab -Purge
```

```powershell
.\Talos.ps1 unmerge -All
```

## Commands

```text
Usage: .\Talos.ps1 <Command> [options]

Commands
  create        Create VMs
  bootstrap     Configure nodes and bootstrap Kubernetes
  kubeconfig    Fetch/activate kubeconfig for a cluster or merged set
  merge         Merge kubeconfigs
  unmerge       Remove a merged kubeconfig set
  clean         Remove VMs and artifacts
  start         Start VMs
  stop          Stop VMs
  list          List clusters and VM states
  disk          Resize OS VHD or attach data disks
  help          Show help
```

## Options

**Global**

* `-Cluster <name>` | `-All` | `-Force`
* `-SwitchName <vSwitch>`
* `-Dest <path>`
* `-TalosISO <path>` | `-TalosVersion <v>`
* `-InstallDisk </dev/sda|...>`
* `-DefaultPrefix <n>`
* `-NoConsole`
* `-ShowDisk`

**create**

* `-ControlPlaneCount <n>` | `-WorkerCount <n>`
* `-ServerCPUs <n>` | `-WorkerCPUs <n>`
* `-ServerMem <size>` | `-WorkerMem <size>`
* `-ServerDisk <size>` | `-WorkerDisk <size>`
* `-VLAN <id>` | `-Bootstrap`

**bootstrap**

* `-Gateway <IPv4>` | `-DNS <IPv4>`
* `-NtpSettleSeconds <n>`
* `-KeepIso`

**merge / unmerge**

* `-Name <name>` | `-All`

**disk**

* `-ResizeDisk <size>` | `-AddDisk <size>`
* `-ControlPlanesOnly` | `-WorkersOnly` | `-Node <vm[,vm...]>`

## License

This project is licensed under the [GPL-3.0](./LICENSE).

## Author

Created and maintained by Firas Ben Nacib - [bennacibfiras@gmail.com](mailto:bennacibfiras@gmail.com)
