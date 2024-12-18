# C2Detector用户手册

## 目录

1. [介绍](#介绍)
2. [前置条件](#前置条件)
3. [安装](#安装)
4. [配置](#配置)
5. [运行C2Detector](#运行c2detector)
6. [理解输出结果](#理解输出结果)
7. [日志记录](#日志记录)
8. [故障排除](#故障排除)
9. [高级配置](#高级配置)
10. [支持](#支持)

---

## 介绍

**C2Detector** 是一款离线工具，旨在监控网络流量数据包并检测潜在的命令与控制（C2）通道行为。利用 Scapy 库进行数据包捕获，并结合机器学习模型进行异常检测，C2Detector 能有效识别网络中的可疑 C&C 通信。

---

## 前置条件

在安装和运行 C2Detector 之前，请确保您的系统满足以下要求：

- **操作系统**：Windows（已在 Windows 10 及以上版本上进行测试）
- **Python**：版本 3.6 或更高
- **权限**：具有捕获网络数据包的管理员权限
- **网络接口**：用于监控的活动网络接口

---

## 安装

### 1. **克隆仓库或下载脚本**

通过克隆仓库或下载 `C2Detector.py` 文件获取 C2Detector 脚本。

```bash
git clone https://github.com/AmyDylen/C2Detector.git
cd C2Detector
```

### 2. **安装所需的 Python 包**

使用 `pip` 安装必要的依赖项：

```bash
pip install scapy numpy psutil pyfiglet
```

> **注意**：如果遇到权限问题，您可能需要以管理员身份运行命令（在 Windows 上）或使用 `sudo`（在基于 Unix 的系统上）。

### 3. **安装 Graphviz**

Graphviz 是图形相关功能所必需的。

- **Windows**：从 [Graphviz 下载页面](https://graphviz.org/download/) 下载并安装 Graphviz。

- **将 Graphviz 添加到系统 PATH**：
  - 进入 `控制面板` > `系统和安全` > `系统` > `高级系统设置`。
  - 点击 `环境变量`。
  - 在 `系统变量` 中找到并选择 `Path` 变量，然后点击 `编辑`。
  - 点击 `新建`，添加 Graphviz 的 `bin` 目录路径（例如 `C:\Program Files\Graphviz\bin`）。
  - 点击 `确定` 保存更改。

### 4. **准备机器学习模型**

确保机器学习模型 `decision_tcp.pkl` 存在于工作目录中。该模型对于检测可疑的 C2 流量至关重要。

> **注意**：如果您没有 `decision_tcp.pkl` 文件，您需要重新训练一个模型或从工具分发包中获取该文件。

---

## 配置

C2Detector 提供了适用于一般用途的默认设置，但您可以根据具体需求调整脚本中的参数以定制其行为。

### 关键配置点：

- **动态池化长度 (`m`)**：设置动态池化的固定长度。默认值为 `30`。
- **数据包延迟阈值**：用于合并数据包的时间间隔。默认值为 `3000` 毫秒。
- **会话超时**：为防止内存溢出，流将在 180 秒后保存。

您可以根据网络环境和检测需求直接在脚本中修改这些值。

---

## 运行C2Detector

### 1. **打开终端或命令提示符**

导航到包含 `C2Detector.py` 脚本的目录。

### 2. **运行脚本**

使用 Python 执行脚本：

```bash
python C2Detector.py
```

### 3. **选择网络接口**

运行后，C2Detector 将显示可用的网络接口列表：

```
Available network interfaces:
1. Ethernet - Up
2. Wi-Fi - Up
3. Loopback Pseudo-Interface 1 - Down
Enter the number of the interface you want to monitor:
```

- **输入**：输入您希望监控的网络接口对应的编号，然后按 `Enter` 键。

### 4. **开始监控**

选择后，C2Detector 将开始在选定的网络接口上监控实时流量：

```
======+++++  C2Detector 系统正在监控网络卡上的实时流量  +++++======
```

可疑活动将被记录并在控制台中实时显示。

---

## 理解输出结果

C2Detector 提供实时反馈和日志记录，以通知您潜在的 C2 活动。

### **控制台输出**


- **网络接口**：列出可用的网络接口及其状态。
  
- **可疑活动通知**：
  
  ```
  Suspected remote control session found: 192.168.1.10:443 <---> 93.184.216.34:8080
  Suspected vulnerability exploitation session traffic file: session_2024-04-27-12-30-00-123456.pcap
  ```

### **日志记录**

所有警告和检测结果将记录在脚本目录下的 `detect.log` 文件中。

---

## 日志记录

C2Detector 会维护一个日志文件，用于记录所有检测到的可疑活动。

### **日志文件位置**

- **文件名**：`detect.log`
- **目录**：与脚本所在目录相同。

### **日志条目格式**

```
2024-04-27 12:30:00,123 - WARNING - C:\Path\To\C2Detector\temp\session_2024-04-27-12-30-00-123456.pcap suspected vulnerability exploitation traffic
```

### **日志信息**

- **时间戳**：记录事件的日期和时间。
- **日志级别**：对于检测到的可疑活动，总是设置为 `WARNING`。
- **消息**：事件描述，包括会话文件路径和可疑性质。

---

## 故障排除

### **常见问题及解决方案**

1. **未找到网络接口**

   - **症状**：脚本输出 `No network interfaces found.` 并退出。
   - **解决方案**：确保您的网络接口处于活动状态，并且您具有访问它们的必要权限。以管理员权限运行脚本。

2. **权限被拒绝错误**

   - **症状**：尝试捕获数据包或写入文件时出现权限不足相关错误。
   - **解决方案**：以管理员身份（Windows）或使用 `sudo` 权限（基于 Unix 的系统）运行脚本。

3. **缺少 `decision_tcp.pkl` 文件**

   - **症状**：提示无法找到或加载模型文件的错误。
   - **解决方案**：确保 `decision_tcp.pkl` 存在于工作目录中。如果缺失，请从工具的分发包中获取该文件或训练您自己的模型。

4. **Graphviz 路径问题**

   - **症状**：与未找到或无法执行 Graphviz 相关的错误。
   - **解决方案**：验证 Graphviz 已安装，并且其 `bin` 目录已正确添加到系统 `PATH` 环境变量中。

5. **高内存使用**

   - **症状**：脚本消耗过多内存，可能导致性能下降或崩溃。
   - **解决方案**：脚本使用动态池化机制并限制并发流的数量。然而，如果内存问题仍然存在，请考虑增加系统的 RAM 或进一步优化脚本。

6. **脚本意外终止**

   - **症状**：脚本意外退出且没有明确的错误信息。
   - **解决方案**：检查 `detect.log` 文件中是否记录了任何异常或错误。确保所有依赖项已正确安装，并且脚本中没有语法错误。

---

## 高级配置

对于希望超出默认设置自定义 C2Detector 行为的用户，可以考虑以下高级配置：

### **1. 调整动态池化长度**

修改 `extract_sessions_features` 函数中的 `m` 参数，以更改动态池化使用的固定长度。

```python
m = 30  # 根据需要修改此值
```

### **2. 更改时间阈值**

调整 `extract_sessions_features` 函数中的数据包延迟阈值，以改变基于时间间隔合并数据包的方式。

```python
if packet_time[i+1] < 3000:  # 调整时间阈值（以毫秒为单位）
```

### **3. 模型选择**

您可以通过修改 `extract_sessions_features` 函数中加载的文件来替换机器学习模型。

```python
with open(os.path.join(os.getcwd(), "decision_tcp.pkl"), 'rb') as f:
    loaded_decisionclf = pickle.load(f)
```

将 `"decision_tcp.pkl"` 替换为您自定义训练模型的路径。

### **4. 日志增强**

通过调整 `log_warning` 函数，包含更多详细信息或集成其他日志系统，来增强日志记录功能。

---

## 支持

如果您遇到本手册未涵盖的问题或需要进一步的帮助，请参考以下途径：

- **仓库问题**：在 [C2Detector GitHub 仓库](https://github.com/AmyDylen/C2Detector/issues) 上提交问题。


---

**免责声明**：C2Detector 是一款功能强大的工具，旨在供授权的安全专业人员和网络管理员使用。请确保您拥有在您的环境中监控和分析网络流量的必要权限。未经授权的使用可能违反隐私法律和组织政策。
