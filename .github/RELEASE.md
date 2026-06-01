# 发版流程

## 预检查

```bash
# 1. 确认 CI 通过
gh run list --branch dev --limit 3

# 2. 全平台 dry-run（手动触发 snapshot 模式）
gh workflow run release.yml -f snapshot=true

# 3. 确认版本号一致
grep "version" common/globals.go
grep "版本" README.md
```

## 发版

```bash
# 1. 确认 release notes 已就绪
cat .github/release-notes/v<VERSION>.md

# 2. 打 tag（在 dev 分支打 RC，在 main 分支打正式版）
git tag v<VERSION>
git push origin v<VERSION>

# CI 自动执行：
#   - goreleaser 全平台构建 + UPX 压缩
#   - 创建 GitHub Release（RC 自动标记 pre-release）
#   - 用 .github/release-notes/ 下的文件覆盖 release body
```

## 版本号规范

| 场景 | 格式 | 分支 | 示例 |
|------|------|------|------|
| 正式版 | `vX.Y.Z` | main | `v2.2.0` |
| 预发布 | `vX.Y.Z-rc` | dev | `v2.2.0-rc` |
| 热修复 | `vX.Y.Z` | main | `v2.2.1` |

## Release Notes 模板

放在 `.github/release-notes/<tag>.md`，格式参考 `v2.2.0-rc.md`。

如果文件不存在，goreleaser 会自动生成基于 commit 的 changelog。

## 正式版发布（RC → 正式）

```bash
# 1. 合并 dev 到 main
git checkout main
git merge dev
git push

# 2. 更新版本号去掉 -rc
# common/globals.go, README.md, README_EN.md

# 3. 准备正式版 release notes
# .github/release-notes/v2.2.0.md

# 4. 打 tag
git tag v2.2.0
git push origin v2.2.0
```
