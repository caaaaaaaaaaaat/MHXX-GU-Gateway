# Windows Release 构建工作流

以后所有版本沿用 V335 发布规范。参考原件为 `.build-desktop/prepare-release.py`、`.build-desktop/release-V335/` 和 `XXGU-Gateway-V335-release-win64.zip`；正式实现已纳入 `package.py` 和 `build.ps1`，不再运行旧的一次性脚本。

## 对外产物

每版发布两个 ZIP，版本号统一读取 `src/main.cpp` 的 `AppVersion`：

- `XXGU-Gateway-Vxxx-release-win64.zip`：根目录恰好两个文件，`XXGU-Gateway.exe`、`使用说明.md`。不加顶层文件夹，不放源码、清单或独立许可证。GPL3、ENet、fmt、zstd 许可全文按 V335 的 `<details>` 格式合并在使用说明末尾。
- `XXGU-Gateway-Vxxx-source.zip`：独立的对应源码包，作为同一个 GitHub Release 的第二个附件。

发布说明源文件放在 `releases/Vxxx.md`，构建后复制到 `.build-desktop/release-Vxxx/发布说明.md`，用于 GitHub Release 正文，不塞入用户 ZIP。内部 `XXGU-Gateway/` 目录及 `SOURCE-CODE.zip`、`BUILD-MANIFEST.json` 是构建中间产物，不作为用户包上传。不要发布旧的 `-win64.zip` 或临时 `-win64-user.zip`。

## 每次发布

1. 修改 `src/main.cpp` 的 `AppVersion`，同步 README、使用说明，并新增对应 `releases/Vxxx.md`。写明本版变化、下载方式和实际验证范围。
2. 在仓库根目录运行：

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File gateway-gui/build.ps1 -RunTests
   ```

3. 构建自动编译、执行设置/后端/核心/CLI 检查、生成两份 ZIP 和发布说明、验证压缩包与源码哈希，最后执行隐藏窗口冒烟测试。失败时不要发布。
4. 核对用户包仅有上述两个文件，EXE 对应本次构建；源码包排除构建目录、私有运行数据、模拟器用户数据和游戏文件。不能把旧版实机验收写成本版新验证。
5. 提交并推送代码。在 GitHub 创建对应版本 Release，将 `发布说明.md` 作为正文，仅上传 `-release-win64.zip` 和 `-source.zip`。用户明确要求代发且发布凭据可用时再执行线上发布。

重新发布前按上面的完整命令构建，以同步程序、发布材料与构建输入哈希。单独执行 `tests/relink-ui.ps1` 不会更新发布 ZIP，不可直接拿旧 ZIP 发布。保留历史版本产物，不覆盖或删除 V335 参考包。
