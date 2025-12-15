# Release Workflow 说明

## 📦 自动创建 Release

我们提供两种方式来自动创建 GitHub Release：

### 方法 1：推送版本标签（推荐）

1. **创建并推送版本标签**：
```bash
# 推送一个版本标签，会自动触发 release workflow
git tag v1.0.0
git push origin v1.0.0
```

2. **GitHub Actions 会自动**：
   - 构建多个平台的可执行文件（Linux, macOS, Windows）
   - 生成 SHA256 校验和
   - 生成 changelog
   - 创建 GitHub Release

### 方法 2：手动触发

1. 进入 GitHub 仓库页面
2. 点击 **Actions** 标签
3. 选择 **Create Release** workflow
4. 点击 **Run workflow** 按钮
5. 选择分支并运行

---

## 🎯 编译输出的平台支持

| 平台 | 架构 | 文件名 |
|------|------|--------|
| Linux | AMD64 | `helm-proxy-linux-amd64` |
| macOS | AMD64 (Intel) | `helm-proxy-darwin-amd64` |
| macOS | ARM64 (Apple Silicon) | `helm-proxy-darwin-arm64` |
| Windows | AMD64 | `helm-proxy-windows-amd64.exe` |

---

## 📋 Release 包含的内容

每个 release 会包含：

1. **可执行文件**（4个平台）
2. **SHA256 校验和文件**（用于验证下载完整性）
3. **README.md**（安装和使用说明）
4. **deploy/** 目录（Kubernetes 部署文件）
5. **Changelog**（自动生成的变更日志）

---

## 🚀 如何使用编译出的包

### Linux/macOS
```bash
# 下载并解压
wget https://github.com/your-username/helm-proxy/releases/download/v1.0.0/helm-proxy-linux-amd64
chmod +x helm-proxy-linux-amd64

# 运行
./helm-proxy-linux-amd64 --port 8443
```

### Windows
```powershell
# 下载并运行
.\helm-proxy-windows-amd64.exe --port 8443
```

### 使用 Docker
```bash
# 使用 GitHub Container Registry
docker pull ghcr.io/your-username/helm-proxy:latest
docker run -p 8443:8443 ghcr.io/your-username/helm-proxy:latest
```

---

## 🔧 自定义构建

如果您需要自定义构建，可以使用以下命令：

```bash
# 构建当前平台
go build -o helm-proxy ./main.go

# 构建特定平台
GOOS=linux GOARCH=amd64 go build -o helm-proxy-linux-amd64 ./main.go
GOOS=darwin GOARCH=arm64 go build -o helm-proxy-darwin-arm64 ./main.go
GOOS=windows GOARCH=amd64 go build -o helm-proxy-windows-amd64.exe ./main.go

# 带优化标志的构建
go build -ldflags="-s -w" -o helm-proxy ./main.go
```

---

## 📊 Workflow 文件说明

- **`.github/workflows/release.yml`**: 新的简化 release workflow
  - 触发条件：推送版本标签或手动触发
  - 构建多平台二进制文件
  - 生成校验和和 changelog
  - 自动创建 GitHub Release

- **`.github/workflows/ci-cd.yml`**: 现有的 CI/CD pipeline
  - 包含完整的测试、构建、部署流程
  - 仅在主分支推送时触发
  - 依赖生产环境部署

---

## 🎉 发布示例

发布 `v1.0.0` 版本：

```bash
# 1. 确认所有更改已提交
git status

# 2. 创建版本标签
git tag v1.0.0

# 3. 推送标签
git push origin v1.0.0

# 4. GitHub Actions 会自动：
#    - 运行测试
#    - 构建二进制文件
#    - 创建 release
#    - 上传所有文件
```

然后访问：https://github.com/your-username/helm-proxy/releases/tag/v1.0.0

---

## ✅ 检查发布状态

1. 进入 GitHub 仓库
2. 点击 **Actions** 标签
3. 查看 **Create Release** workflow 的运行状态
4. 完成后检查 **Releases** 页面

---

## 📝 注意事项

1. **版本号格式**：必须遵循语义化版本（SemVer），如 `v1.0.0`, `v1.2.3`
2. **权限**：需要仓库的 **Actions** 和 **Releases** 权限
3. **触发条件**：
   - 推送以 `v` 开头的标签（例：`v1.0.0`）
   - 手动在 GitHub Actions 页面触发
4. **二进制文件大小**：使用 `-ldflags="-s -w"` 减小文件大小

---

## 🎊 成功！

现在您可以轻松地为项目创建 release 包了！每次推送版本标签，GitHub 就会自动构建并发布所有平台的二进制文件。
