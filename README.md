# KernelLover-AV

A comprehensive hypervisor-based antivirus solution that combines kernel-level file system monitoring, YARA pattern matching, and Intel VMX virtualization technologies to provide multi-layered protection against malware and security threats.

## 🎓 About This Project

This project was developed as my graduation project, demonstrating advanced Windows kernel development, hypervisor technology, and cybersecurity concepts. KernelLover-AV implements a defense-in-depth security approach using cutting-edge technologies including VMX hypervisor, kernel mini-filter drivers, and real-time malware detection.

## 🏗️ System Architecture

KernelLover-AV follows a layered security architecture with components operating in both kernel and user modes:

```
┌─────────────────────────────────────────────────────────┐
│                    User Mode                            │
├─────────────────┬─────────────────┬─────────────────────┤
│ ControlFilterApp│   TheCYaraAgent │  HypervisorUsermode │
├─────────────────┼─────────────────┼─────────────────────┤
│                    Kernel Mode                          │
├─────────────────┬─────────────────┬─────────────────────┤
│FileMonitorMini- │       File      │   HypervisorTest    │
│    Filter       │     System      │                     │
└─────────────────┴─────────────────┴─────────────────────┘
```

## 🔧 Core Components

### 1. File Monitoring Subsystem
- **FileMonitorMiniFilter**: Kernel-mode mini-filter driver that intercepts file system operations
- Real-time file operation analysis and policy enforcement
- Pre/post-operation callbacks for comprehensive monitoring

### 2. YARA Integration Engine
- **TheCYaraAgent**: Pattern matching engine for malware detection
- Dynamic YARA rule updates and management
- High-performance scanning with comprehensive rule database

### 3. Hypervisor Technology
- **HypervisorTest**: Kernel-mode hypervisor leveraging Intel VMX
- **HypervisorUsermode**: User-mode control interface
- Hardware-level isolation and monitoring capabilities
- Extended Page Tables (EPT) and VM control structures

### 4. Central Control System
- **ControlFilterApp**: Unified management interface
- Component coordination and configuration
- Event logging and system monitoring

## 🛡️ Security Features

### Defense-in-Depth Strategy
1. **File System Layer**: Intercepts and analyzes all file operations
2. **Pattern Matching Layer**: Identifies known malware signatures using YARA
3. **Virtualization Layer**: Provides hardware-level isolation and containment

### Security Policy Framework
- **YARA Rule-Based Detection**: Security policies are enforced through loaded YARA rules
- **Dynamic Rule Management**: Rules can be updated and managed through the control application
- **Configurable Detection Patterns**: Flexible pattern matching based on current rule set
### Key Capabilities
- Hardware-assisted security through Intel VMX
- Configurable security policies and rules
- x64 architecture support
- Comprehensive logging and monitoring

## 🚀 Getting Started

### Prerequisites
- Windows development environment with WDK (Windows Driver Kit)
- Intel processor with VMX support (for hypervisor functionality)
- Administrative privileges for driver installation
- Visual Studio with kernel development tools

### Installation
1. Build the solution using Visual Studio with WDK
2. Install the kernel drivers using appropriate signing certificates
3. Deploy the user-mode applications
4. Configure YARA rules and security policies

### Usage
1. Start the ControlFilterApp as administrator
2. Configure file monitoring policies
3. Update YARA rule database
4. Enable hypervisor protection (if supported)
5. Monitor system events and security alerts

## 📋 System Requirements

- **OS**: Windows 10/11 (x64 recommended)
- **Processor**: Intel with VMX support (for full functionality)
- **Memory**: Minimum 4GB RAM
- **Privileges**: Administrator rights required
- **Development**: Visual Studio + WDK for building from source

## 🔍 Technical Highlights

### Advanced Kernel Programming
- Mini-filter driver development
- IOCTL communication between kernel and user modes
- Inverted call patterns and asynchronous I/O
- Cancel-safe IRP handling

### Hypervisor Implementation
- Intel VMX technology integration
- Extended Page Tables (EPT) management
- VM exit handling and control structures
- Hardware-assisted security monitoring

### Security Engineering
- Real-time threat detection
- Pattern matching algorithms
- File system security policies
- Multi-layered defense mechanisms

## 📚 Documentation Structure

- **Architecture**: Detailed system design and component interactions
- **Components**: In-depth technical specifications for each module
- **Implementation**: Code structure and development guidelines
- **Deployment**: Installation and configuration procedures

## ⚠️ Important Notes

- This software requires kernel-level access and should be used with caution
- Proper driver signing is required for production deployment
- **Hypervisor functionality currently works only in single-core OS environments**
- Administrative privileges are mandatory for all operations
- The file monitoring and YARA detection components work reliably in all environments
- Future updates will enhance hypervisor compatibility for multi-core systems

## 🎯 Project Outcomes

This graduation project demonstrates:
- Advanced Windows kernel development skills
- Understanding of hypervisor and virtualization technologies
- Implementation of enterprise-grade security solutions
- Integration of multiple complex systems and technologies
- Real-world application of cybersecurity principles
## DeepWiki
See a full overview on the architecture and how my project works at this link: https://deepwiki.com/OmarShehata11/KernelLover
## 📝 License

This project was developed for educational purposes as a graduation project. Please ensure compliance with all applicable laws and regulations if using or modifying this code.

---

**Note**: This is an educational project developed to demonstrate advanced kernel programming and cybersecurity concepts. Use responsibly and ensure proper testing in isolated environments.
